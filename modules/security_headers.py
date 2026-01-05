import requests

def analyze(url):
    try:
        resp = requests.get(url, timeout=10)
        headers = resp.headers
    except Exception as e:
        return [{'name': 'Error', 'status': 'Could not retrieve headers', 'impact': str(e)}]
    results = []
    # Content-Security-Policy
    csp = headers.get('Content-Security-Policy')
    if not csp:
        results.append({'name': 'Content-Security-Policy', 'status': '❌ Absent', 'impact': 'XSS risk'})
    else:
        if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
            results.append({'name': 'Content-Security-Policy', 'status': '⚠️ Weak', 'impact': 'Limited XSS protection'})
        else:
            results.append({'name': 'Content-Security-Policy', 'status': '✔ Present', 'impact': 'Protects against XSS'})
    # Strict-Transport-Security
    hsts = headers.get('Strict-Transport-Security')
    if not hsts:
        results.append({'name': 'Strict-Transport-Security', 'status': '❌ Absent', 'impact': 'HTTP downgrade risk'})
    else:
        results.append({'name': 'Strict-Transport-Security', 'status': '✔ Present', 'impact': 'Protects against downgrade'})
    # X-Frame-Options
    xfo = headers.get('X-Frame-Options')
    if not xfo:
        results.append({'name': 'X-Frame-Options', 'status': '❌ Absent', 'impact': 'Clickjacking risk'})
    else:
        results.append({'name': 'X-Frame-Options', 'status': '✔ Present', 'impact': 'Protects against clickjacking'})
    # X-Content-Type-Options
    xcto = headers.get('X-Content-Type-Options')
    if not xcto:
        results.append({'name': 'X-Content-Type-Options', 'status': '❌ Absent', 'impact': 'Malicious content execution risk'})
    else:
        results.append({'name': 'X-Content-Type-Options', 'status': '✔ Present', 'impact': 'Protects against malicious content execution'})
    # Referrer-Policy
    refpol = headers.get('Referrer-Policy')
    if not refpol:
        results.append({'name': 'Referrer-Policy', 'status': '❌ Absent', 'impact': 'Referrer information leakage risk'})
    else:
        results.append({'name': 'Referrer-Policy', 'status': '✔ Present', 'impact': 'Protects user privacy'})
    # Permissions-Policy
    ppol = headers.get('Permissions-Policy')
    if not ppol:
        results.append({'name': 'Permissions-Policy', 'status': '❌ Absent', 'impact': 'Browser API abuse risk'})
    else:
        results.append({'name': 'Permissions-Policy', 'status': '✔ Present', 'impact': 'Restricts access to browser APIs'})
    return results
