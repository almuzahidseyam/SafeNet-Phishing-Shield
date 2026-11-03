"""Local research assistant. Missing evidence never becomes a safe verdict."""
import datetime
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import tldextract
from safe_http import normalize_url, BlockedURL

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / '.env')
EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


def run_worker(task, payload, timeout, *, worker=ROOT / 'network_worker.py'):
    try:
        result = subprocess.run([sys.executable, str(worker), task], input=json.dumps(payload),
                                capture_output=True, text=True, encoding='utf-8', timeout=timeout,
                                cwd=ROOT, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        if result.returncode != 0:
            raise ValueError('Worker failed')
        result = json.loads(result.stdout)
        if result.get('status') not in ('ok', 'blocked', 'unavailable'):
            raise ValueError('Invalid worker result')
        return result
    except subprocess.TimeoutExpired:
        return {'status': 'unavailable', 'error': 'Lookup timed out. No safety verdict is available.'}
    except (ValueError, OSError):
        return {'status': 'unavailable', 'error': 'Lookup unavailable. No safety verdict is available.'}


def unavailable(reason):
    return {'status': 'unavailable', 'risk_score': None, 'verdict': 'Analysis unavailable', 'reasoning_bengali': reason}


def extract_url_features(url):
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    host = parsed.hostname
    ext = EXTRACTOR(host)
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    return {
        'hostname': host, 'domain': ext.top_domain_under_public_suffix or host,
        'subdomain': ext.subdomain, 'is_https': parsed.scheme == 'https',
        'url_length': len(normalized), 'has_ip_in_domain': is_ip,
        'hyphens_in_domain': host.count('-'),
        'uses_punycode': any(label.startswith('xn--') for label in host.split('.')),
        'suspicious_words': [word for word in ('free', 'offer', 'bkash', 'daraz', 'nagad', 'lottery', 'login', 'update', 'verify', 'account', 'gov', 'bcs', 'job') if word in normalized.lower()],
    }


def get_whois_data(domain, *, runner=run_worker):
    """RDAP replaces the unbounded WHOIS thread; the whole lookup has four seconds."""
    result = runner('rdap', {'domain': domain}, 4)
    if result['status'] != 'ok':
        return {'status': 'unavailable', 'domain_age_days': None, 'registrar': None}
    data = result['data']
    age = None
    for event in data.get('events', []):
        if event.get('eventAction') == 'registration':
            try:
                created = datetime.datetime.fromisoformat(event['eventDate'].replace('Z', '+00:00'))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=datetime.timezone.utc)
                value = (datetime.datetime.now(datetime.timezone.utc) - created).days
                age = value if value >= 0 else None
            except (ValueError, TypeError, KeyError):
                pass
    registrar = None
    for entity in data.get('entities', []):
        if 'registrar' in entity.get('roles', []):
            card = entity.get('vcardArray', [None, []])
            if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list):
                for field in card[1]:
                    if isinstance(field, list) and len(field) > 3 and field[0] == 'fn' and isinstance(field[3], str):
                        registrar = field[3][:200]
    return {'status': 'ok', 'domain_age_days': age, 'registrar': registrar}


def analyze_with_ai(features, registry, tls, page, *, runner=run_worker):
    if not os.getenv('GEMINI_API_KEY') or not os.getenv('GEMINI_MODEL'):
        return unavailable('Gemini API key বা model সেট করা হয়নি। নিরাপত্তা সম্পর্কে সিদ্ধান্ত দেওয়া যাচ্ছে না।')
    result = runner('ai', {'url_features': features, 'registry': registry, 'tls': tls, 'page': page}, 20)
    if result['status'] != 'ok':
        return unavailable('AI বিশ্লেষণ পাওয়া যায়নি। এটিকে নিরাপদ হওয়ার প্রমাণ হিসেবে ধরবেন না।')
    data = result.get('data')
    if not isinstance(data, dict):
        return unavailable('AI একটি অসম্পূর্ণ ফল দিয়েছে।')
    score, reason = data.get('risk_score'), data.get('reasoning_bengali')
    if type(score) is not int or not 0 <= score <= 100 or not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 2000:
        return unavailable('AI ফলের গঠন সঠিক নয়। নিরাপত্তা সম্পর্কে সিদ্ধান্ত দেওয়া যাচ্ছে না।')
    return {'status': 'ok', 'risk_score': score,
            'verdict': 'High risk indicators' if score >= 70 else 'Suspicious indicators' if score >= 30 else 'Few detected indicators',
            'reasoning_bengali': reason.strip()}


def full_scan(url, use_ai=False, *, runner=run_worker):
    result = {'status': 'unavailable', 'url_features': {}, 'whois_features': {}, 'ssl_details': {}, 'dom_context': {},
              'ai_analysis': unavailable('AI analysis was not requested.')}
    try:
        normalized = normalize_url(url)
        result['url_features'] = extract_url_features(normalized)
    except BlockedURL as error:
        return {**result, 'status': 'blocked', 'error': str(error)}
    page = runner('page', {'url': normalized}, 8)
    if page['status'] != 'ok':
        return {**result, 'status': page['status'], 'error': page.get('error', 'Page inspection unavailable.')}
    data = page['data']
    try:
        result['url_features'] = extract_url_features(data['url'])
        result['final_url'] = data['url']
        result['redirects'] = data['redirects']
        soup = BeautifulSoup(data['html'], 'html.parser')
        title = soup.title.get_text(' ', strip=True)[:150] if soup.title else 'No title'
        meta = soup.find('meta', attrs={'name': 'description'})
        description = str(meta.get('content', ''))[:250] if meta else ''
        result['dom_context'] = {'page_title': title, 'meta_description': description}
        certificate = data.get('certificate')
        issuer = dict(item for group in certificate.get('issuer', []) for item in group) if certificate else {}
        result['ssl_details'] = {'verified': bool(certificate), 'issuer': issuer.get('organizationName', issuer.get('commonName'))}
        result['whois_features'] = ({'status': 'unavailable', 'domain_age_days': None, 'registrar': None}
                                    if result['url_features']['has_ip_in_domain'] else get_whois_data(result['url_features']['domain'], runner=runner))
        result['status'] = 'ok'
        if use_ai:
            result['ai_analysis'] = analyze_with_ai(result['url_features'], result['whois_features'], result['ssl_details'], result['dom_context'], runner=runner)
        return result
    except (ValueError, TypeError, KeyError, AttributeError):
        return {**result, 'status': 'unavailable', 'error': 'A remote response was incomplete or unsupported.'}
