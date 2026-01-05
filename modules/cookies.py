import requests
from http.cookies import SimpleCookie

def analyze(url):
    try:
        resp = requests.get(url, timeout=10)
        cookies = resp.cookies
        set_cookie = resp.headers.get('Set-Cookie', '')
    except Exception as e:
        return [{'name': 'Error', 'status': 'Could not retrieve cookies', 'impact': str(e)}]
    results = []
    if set_cookie:
        cookie = SimpleCookie()
        cookie.load(set_cookie)
        for key in cookie:
            morsel = cookie[key]
            flags = []
            impact = []
            if not morsel['secure']:
                flags.append('Not Secure')
                impact.append('May be sent over HTTP')
            if not morsel['httponly']:
                flags.append('Not HttpOnly')
                impact.append('Accessible from JS → session theft risk')
            if not morsel['samesite']:
                flags.append('No SameSite')
                impact.append('CSRF risk')
            results.append({'name': key, 'status': ', '.join(flags) if flags else '✔ Secure', 'impact': '; '.join(impact) if impact else 'No evident risks'})
    else:
        results.append({'name': 'Cookies', 'status': 'No cookies detected', 'impact': ''})
    return results
