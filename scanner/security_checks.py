import requests
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

urllib_disable = True
try:
    import urllib3
    urllib3.disable_warnings()
except:
    pass

SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'HSTS',
        'severity': 'HIGH',
        'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
    },
    'Content-Security-Policy': {
        'description': 'Content Security Policy',
        'severity': 'HIGH',
        'recommendation': 'Add a CSP header to restrict sources of scripts and styles.',
    },
    'X-Frame-Options': {
        'description': 'X-Frame-Options',
        'severity': 'MEDIUM',
        'recommendation': 'Add: X-Frame-Options: DENY',
    },
    'X-Content-Type-Options': {
        'description': 'X-Content-Type-Options',
        'severity': 'MEDIUM',
        'recommendation': 'Add: X-Content-Type-Options: nosniff',
    },
    'Referrer-Policy': {
        'description': 'Referrer Policy',
        'severity': 'LOW',
        'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
    },
    'Permissions-Policy': {
        'description': 'Permissions Policy',
        'severity': 'LOW',
        'recommendation': 'Add: Permissions-Policy: geolocation=(), microphone=()',
    },
}

COMMON_PORTS = [
    (21, 'FTP'),
    (22, 'SSH'),
    (23, 'Telnet'),
    (80, 'HTTP'),
    (443, 'HTTPS'),
    (3306, 'MySQL'),
    (5432, 'PostgreSQL'),
    (6379, 'Redis'),
    (27017, 'MongoDB'),
]

DANGEROUS_PORTS = {21, 23, 3306, 5432, 6379, 27017}


def normalize_url(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def check_headers(response_headers):
    results = []
    for header, info in SECURITY_HEADERS.items():
        found = any(k.lower() == header.lower() for k in response_headers)
        results.append({
            'name': info['description'],
            'category': 'headers',
            'passed': found,
            'severity': info['severity'],
            'detail': f'{"Present" if found else "Missing"}: {header}',
            'recommendation': info['recommendation'],
        })
    return results


def check_https_redirect(hostname):
    result = {
        'name': 'HTTPS Redirect',
        'category': 'transport',
        'passed': False,
        'severity': 'HIGH',
        'detail': '',
        'recommendation': 'Redirect all HTTP traffic to HTTPS.',
    }
    try:
        resp = requests.get(f'http://{hostname}', timeout=4, allow_redirects=True)
        if resp.url.startswith('https://'):
            result['passed'] = True
            result['detail'] = 'HTTP correctly redirects to HTTPS.'
        else:
            result['detail'] = 'HTTP does not redirect to HTTPS.'
    except Exception as e:
        result['detail'] = f'Could not check: {str(e)[:80]}'
    return result


def check_ssl(hostname):
    result = {
        'name': 'SSL Certificate',
        'category': 'ssl',
        'passed': False,
        'severity': 'HIGH',
        'detail': '',
        'recommendation': 'Get a valid SSL certificate from a trusted CA like Let\'s Encrypt.',
        'extra': {}
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=6), server_hostname=hostname) as s:
            cert = s.getpeercert()
            expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            result['passed'] = days_left > 14
            result['extra'] = {
                'expires': expires.strftime('%Y-%m-%d'),
                'days_left': days_left,
                'protocol': s.version(),
            }
            result['detail'] = f'Certificate valid. Expires in {days_left} days ({expires.strftime("%Y-%m-%d")}). Protocol: {s.version()}.'
    except Exception as e:
        result['detail'] = f'SSL check failed: {str(e)[:80]}'
    return result


def check_ports(hostname):
    results = []
    for port, service in COMMON_PORTS:
        is_open = False
        try:
            sock = socket.create_connection((hostname, port), timeout=0.8)
            sock.close()
            is_open = True
        except:
            pass

        if is_open:
            dangerous = port in DANGEROUS_PORTS
            results.append({
                'name': f'Port {port} ({service})',
                'category': 'ports',
                'passed': not dangerous,
                'severity': 'HIGH' if dangerous else 'INFO',
                'detail': f'Port {port} ({service}) is open.' + (' Should not be public!' if dangerous else ''),
                'recommendation': f'Firewall port {port} from public access.' if dangerous else 'Intentionally open.',
            })
    return results


def check_server_leakage(headers):
    leaked = {h: v for h, v in headers.items() if h in ['Server', 'X-Powered-By']}
    return {
        'name': 'Server Info Leakage',
        'category': 'headers',
        'passed': len(leaked) == 0,
        'severity': 'MEDIUM',
        'detail': f'Exposed: {leaked}' if leaked else 'No technology headers exposed.',
        'recommendation': 'Remove Server and X-Powered-By headers in your web server config.',
    }


def compute_score(checks):
    weights = {'HIGH': 25, 'MEDIUM': 10, 'LOW': 5, 'INFO': 0}
    deduction = sum(weights.get(c['severity'], 0) for c in checks if not c['passed'])
    score = max(0, 100 - deduction)
    if score >= 85:
        risk = 'LOW'
    elif score >= 60:
        risk = 'MEDIUM'
    elif score >= 35:
        risk = 'HIGH'
    else:
        risk = 'CRITICAL'
    return score, risk


def run_scan(url):
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path.split('/')[0]

    data = {
        'url': url,
        'hostname': hostname,
        'checks': [],
        'errors': [],
    }

    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        headers = dict(response.headers)
        data['status_code'] = response.status_code
        data['checks'].extend(check_headers(headers))
        data['checks'].append(check_server_leakage(headers))
    except Exception as e:
        data['errors'].append(str(e)[:100])

    data['checks'].append(check_https_redirect(hostname))
    data['checks'].append(check_ssl(hostname))
    data['checks'].extend(check_ports(hostname))

    score, risk = compute_score(data['checks'])
    data['score'] = score
    data['risk_level'] = risk

    return data