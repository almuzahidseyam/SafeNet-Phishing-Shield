import ipaddress
import json
from pathlib import Path
import socket
import sys
import time
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from safe_http import BlockedURL, normalize_url, resolve_public, fetch_public, request_once, MAX_BODY
from core_engine import analyze_with_ai, extract_url_features, full_scan, get_whois_data, run_worker


@pytest.mark.parametrize('url', ['file:///etc/passwd', 'ftp://example.com', 'http://user:pass@example.com', 'http://example.com:8000', 'http://localhost/', 'http://example.com/\r\nHeader:x', 'https://example.com\\@evil.com', '', 'x' * 2049])
def test_invalid_urls(url):
    with pytest.raises(BlockedURL): normalize_url(url)


@pytest.mark.parametrize('address', ['127.0.0.1', '10.2.3.4', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '192.0.2.1', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1', '64:ff9b::7f00:1', '2002:7f00:1::'])
def test_nonpublic_destinations_never_connect(address):
    with pytest.raises(BlockedURL): resolve_public(address, 80)


def test_mixed_dns_answers_fail_closed():
    resolver = lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443)) for ip in ['8.8.8.8', '127.0.0.1']]
    with pytest.raises(BlockedURL): resolve_public('public.example', 443, resolver)


def test_redirect_is_validated_before_second_connection():
    calls = []
    def resolve(host, port):
        if host == 'public.example': return '8.8.8.8'
        return resolve_public(host, port)
    def request(url, ip, **kwargs):
        calls.append((url, ip))
        return {'status': 302, 'headers': {'location': 'http://169.254.169.254/latest/meta-data'}, 'body': b''}
    with pytest.raises(BlockedURL): fetch_public('https://public.example', resolve=resolve, request=request)
    assert calls == [('https://public.example/', '8.8.8.8')]


def test_dns_is_pinned_for_request_and_api_redirects_do_not_forward_secrets():
    calls = []
    def resolve(host, port): calls.append(('dns', host)); return '8.8.8.8'
    def request(url, ip, **kwargs):
        calls.append(('connect', ip))
        return {'status': 302, 'headers': {'location': 'https://elsewhere.example'}, 'body': b''}
    with pytest.raises(BlockedURL): fetch_public('https://api.example', resolve=resolve, request=request, method='POST', headers={'x-goog-api-key': 'fixture'})
    assert calls == [('dns', 'api.example'), ('connect', '8.8.8.8')]


def test_redirect_loop_is_bounded():
    calls = []
    def request(url, ip, **kwargs):
        calls.append(url)
        return {'status': 301, 'headers': {'location': '/again'}, 'body': b''}
    with pytest.raises(ValueError, match='Too many'): fetch_public('https://public.example', resolve=lambda *a: '8.8.8.8', request=request)
    assert len(calls) == 6


@pytest.mark.parametrize('headers,body', [({'Content-Length': str(MAX_BODY + 1)}, b''), ({}, b'x' * (MAX_BODY + 1)), ({'Content-Encoding': 'gzip'}, b'compressed')])
def test_size_and_encoding_bounds_without_real_network(monkeypatch, headers, body):
    class Sock:
        def settimeout(self, value): pass
        def connect(self, target): assert target == ('8.8.8.8', 80)
        def close(self): pass
    class Response:
        status = 200
        def getheaders(self): return headers.items()
        def read(self, size): assert size == MAX_BODY + 1; return body
    class Connection:
        def __init__(self, *args, **kwargs): pass
        def request(self, method, path, **kwargs): assert path == '/'
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr('safe_http.socket.socket', lambda *args: Sock())
    monkeypatch.setattr('safe_http.http.client.HTTPConnection', Connection)
    with pytest.raises(ValueError): request_once('http://public.example/', '8.8.8.8')


def test_missing_key_and_provider_errors_never_become_zero_risk(monkeypatch):
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    result = analyze_with_ai({}, {}, {}, {}, runner=lambda *args: pytest.fail('Must not call AI without configuration'))
    assert result['risk_score'] is None and result['status'] == 'unavailable'
    monkeypatch.setenv('GEMINI_API_KEY', 'fixture'); monkeypatch.setenv('GEMINI_MODEL', 'fixture-model')
    result = analyze_with_ai({}, {}, {}, {}, runner=lambda *args: {'status': 'unavailable'})
    assert result['risk_score'] is None


@pytest.mark.parametrize('data', [None, [], {}, {'risk_score': -1, 'reasoning_bengali': 'x'}, {'risk_score': True, 'reasoning_bengali': 'x'}, {'risk_score': '0', 'reasoning_bengali': 'x'}, {'risk_score': 0, 'reasoning_bengali': ''}])
def test_invalid_ai_schema_is_neutral(monkeypatch, data):
    monkeypatch.setenv('GEMINI_API_KEY', 'fixture'); monkeypatch.setenv('GEMINI_MODEL', 'fixture-model')
    result = analyze_with_ai({}, {}, {}, {}, runner=lambda *args: {'status': 'ok', 'data': data})
    assert result['status'] == 'unavailable' and result['risk_score'] is None


def test_valid_zero_score_is_not_a_safe_certificate(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY', 'fixture'); monkeypatch.setenv('GEMINI_MODEL', 'fixture-model')
    result = analyze_with_ai({}, {}, {}, {}, runner=lambda *args: {'status': 'ok', 'data': {'risk_score': 0, 'reasoning_bengali': 'Insufficient indicators', 'verdict': 'Safe'}})
    assert result['status'] == 'ok' and result['risk_score'] == 0
    assert result['verdict'] == 'Few detected indicators'


def test_numeric_domain_and_internationalized_domain_are_not_attacks_by_definition():
    assert extract_url_features('https://shop123.com')['has_ip_in_domain'] is False
    assert extract_url_features('https://8.8.8.8')['has_ip_in_domain'] is True
    assert extract_url_features('https://বাংলা.com')['uses_punycode'] is True


def test_blocked_page_stops_registry_and_ai():
    calls = []
    def runner(task, payload, timeout): calls.append(task); return {'status': 'blocked', 'error': 'Private destination'}
    result = full_scan('http://127.0.0.1/', use_ai=True, runner=runner)
    assert result['status'] == 'blocked' and result['ai_analysis']['risk_score'] is None
    assert calls == ['page']


def test_lookup_deadline_kills_slow_process(tmp_path):
    worker = tmp_path / 'slow.py'
    worker.write_text('import time\ntime.sleep(30)\nprint("{}")')
    started = time.monotonic()
    result = run_worker('rdap', {}, .25, worker=worker)
    assert time.monotonic() - started < 3
    assert result['status'] == 'unavailable' and 'timed out' in result['error']


def test_registry_uses_four_second_budget_and_timezone_aware_dates():
    calls = []
    def runner(task, payload, timeout):
        calls.append((task, timeout))
        return {'status': 'ok', 'data': {'events': [{'eventAction': 'registration', 'eventDate': '2020-01-01T00:00:00Z'}]}}
    result = get_whois_data('example.com', runner=runner)
    assert result['domain_age_days'] > 0 and calls == [('rdap', 4)]


def test_full_scan_does_not_send_to_ai_without_opt_in():
    calls = []
    def runner(task, payload, timeout):
        calls.append(task)
        if task == 'page': return {'status': 'ok', 'data': {'url': 'https://example.com/', 'redirects': 0, 'certificate': None, 'html': '<title>Example</title>'}}
        return {'status': 'unavailable'}
    result = full_scan('https://example.com/', runner=runner)
    assert result['status'] == 'ok' and result['dom_context']['page_title'] == 'Example'
    assert calls == ['page', 'rdap'] and result['ai_analysis']['risk_score'] is None
