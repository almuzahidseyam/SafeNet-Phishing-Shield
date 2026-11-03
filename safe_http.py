"""Bounded HTTP transport with validated, pinned public IP destinations.

Call from network_worker.py through core_engine.run_worker: its process deadline
also bounds blocking DNS, slow headers and slow TLS handshakes.
"""
import http.client
import ipaddress
import re
import socket
import ssl
import certifi
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

MAX_BODY = 262144


class BlockedURL(ValueError):
    pass


def normalize_url(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise BlockedURL('Enter a URL with at most 2,048 characters.')
    value = value.strip()
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or '\\' in value:
        raise BlockedURL('Whitespace, control characters and backslashes are not allowed in URLs.')
    if '://' not in value:
        value = 'https://' + value
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or '').rstrip('.').encode('idna').decode('ascii').lower()
        if parsed.scheme not in ('http', 'https') or parsed.username is not None or parsed.password is not None or '%' in host:
            raise BlockedURL('Only HTTP(S) URLs without embedded credentials are allowed.')
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        if port != (443 if parsed.scheme == 'https' else 80):
            raise BlockedURL('Only the standard HTTP and HTTPS ports are allowed.')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or '.' not in host or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
                raise BlockedURL('Enter a public domain name or public IP address.')
        authority = f'[{host}]' if ':' in host else host
        return urlunsplit((parsed.scheme, authority, quote(parsed.path or '/', safe="/%:@!$&'()*+,;=-._~"), quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~"), ''))
    except (ValueError, UnicodeError) as error:
        if isinstance(error, BlockedURL):
            raise
        raise BlockedURL('The URL is invalid.') from None


def is_public_ip(value):
    ip = ipaddress.ip_address(value)
    if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped or ip.sixtofour or ip.teredo:
            return False
        if ip in ipaddress.ip_network('64:ff9b::/96') or ip in ipaddress.ip_network('64:ff9b:1::/48'):
            return False
    return True


def resolve_public(host, port, resolver=socket.getaddrinfo):
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        addresses = list(dict.fromkeys(record[4][0] for record in resolver(host, port, type=socket.SOCK_STREAM)))
    if not addresses or any(not is_public_ip(ip) for ip in addresses):
        raise BlockedURL('Private, loopback, reserved or mixed public/private destinations are blocked.')
    return addresses[0]


def request_once(url, ip, *, method='GET', body=None, headers=None, timeout=3):
    parsed = urlsplit(url)
    port = 443 if parsed.scheme == 'https' else 80
    # Connect directly to the previously validated address: no second DNS lookup.
    sock = socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    certificate = None
    try:
        sock.connect((ip, port))
        if parsed.scheme == 'https':
            context = ssl.create_default_context(cafile=certifi.where())
            context.set_alpn_protocols(['http/1.1'])
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
            certificate = sock.getpeercert()
        connection.sock = sock
        request_headers = {'User-Agent': 'SafeNet-Research/1.1', 'Accept-Encoding': 'identity', 'Connection': 'close'}
        request_headers.update(headers or {})
        connection.request(method, urlunsplit(('', '', parsed.path or '/', parsed.query, '')), body=body, headers=request_headers)
        response = connection.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        # Do not read untrusted redirect bodies.
        if response.status in (301, 302, 303, 307, 308):
            data = b''
        else:
            if response_headers.get('content-encoding', 'identity').lower() not in ('', 'identity'):
                raise ValueError('Compressed responses are not inspected.')
            size = response_headers.get('content-length')
            if size is not None and (not size.isdecimal() or int(size) > MAX_BODY):
                raise ValueError('Response is too large.')
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise ValueError('Response is too large.')
        return {'status': response.status, 'headers': response_headers, 'body': data, 'certificate': certificate}
    finally:
        connection.close()
        sock.close()


def fetch_public(url, *, resolve=resolve_public, request=request_once, method='GET', body=None, headers=None):
    current = normalize_url(url)
    for redirect in range(6):
        parsed = urlsplit(current)
        ip = resolve(parsed.hostname, 443 if parsed.scheme == 'https' else 80)
        result = request(current, ip, method=method, body=body, headers=headers)
        if result['status'] in (301, 302, 303, 307, 308):
            if method != 'GET':
                raise BlockedURL('Redirects are not allowed for API requests.')
            if redirect == 5:
                raise ValueError('Too many redirects.')
            location = result['headers'].get('location')
            if not location:
                raise ValueError('Redirect has no destination.')
            current = normalize_url(urljoin(current, location))
            continue
        if not 200 <= result['status'] < 300:
            raise ValueError(f'Destination returned HTTP {result["status"]}.')
        return {**result, 'url': current, 'redirects': redirect}
    raise ValueError('Too many redirects.')
