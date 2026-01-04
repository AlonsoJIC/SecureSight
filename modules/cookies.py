import requests
from http.cookies import SimpleCookie

def analyze(url):
    try:
        resp = requests.get(url, timeout=10)
        cookies = resp.cookies
        set_cookie = resp.headers.get('Set-Cookie', '')
    except Exception as e:
        return [{'name': 'Error', 'status': 'No se pudo obtener cookies', 'impact': str(e)}]
    results = []
    if set_cookie:
        cookie = SimpleCookie()
        cookie.load(set_cookie)
        for key in cookie:
            morsel = cookie[key]
            flags = []
            impact = []
            if not morsel['secure']:
                flags.append('No Secure')
                impact.append('Puede ser enviada por HTTP')
            if not morsel['httponly']:
                flags.append('No HttpOnly')
                impact.append('Accesible desde JS → riesgo de robo de sesión')
            if not morsel['samesite']:
                flags.append('No SameSite')
                impact.append('Riesgo de CSRF')
            results.append({'name': key, 'status': ', '.join(flags) if flags else '✔ Segura', 'impact': '; '.join(impact) if impact else 'Sin riesgos evidentes'})
    else:
        results.append({'name': 'Cookies', 'status': 'No se detectaron cookies', 'impact': ''})
    return results
