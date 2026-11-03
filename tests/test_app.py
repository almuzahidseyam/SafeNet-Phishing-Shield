from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from streamlit.testing.v1 import AppTest


def test_blocked_lookup_ui_never_shows_risk_gauge(monkeypatch):
    monkeypatch.setattr('core_engine.full_scan', lambda *args, **kwargs: {'status': 'blocked', 'error': 'Private destination blocked'})
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py')).run()
    app.text_input[0].set_value('http://127.0.0.1/')
    app.button[0].click().run()
    assert not app.exception
    assert 'Private destination' in app.warning[0].value
    assert len(app.metric) == 0


def test_observed_evidence_with_unavailable_ai_has_no_risk_metric(monkeypatch):
    monkeypatch.setattr('core_engine.full_scan', lambda *args, **kwargs: {
        'status': 'ok', 'final_url': 'https://example.com/', 'redirects': 0,
        'url_features': {'has_ip_in_domain': False, 'uses_punycode': False, 'suspicious_words': []},
        'whois_features': {'domain_age_days': None}, 'ssl_details': {'verified': True},
        'dom_context': {'page_title': '<img src=x onerror=alert(1)>', 'meta_description': ''},
        'ai_analysis': {'status': 'unavailable', 'risk_score': None, 'reasoning_bengali': 'Unavailable'},
    })
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py')).run()
    app.text_input[0].set_value('https://example.com/'); app.button[0].click().run()
    assert not app.exception
    assert [metric.label for metric in app.metric] == ['Domain age', 'TLS certificate']
    assert 'No risk score' in app.info[0].value
    assert any('<img' in text.value for text in app.text)
