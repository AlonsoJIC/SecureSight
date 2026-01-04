import requests

def analyze(url):
    try:
        resp = requests.get(url, timeout=10)
        headers = resp.headers
    except Exception as e:
        return [{'name': 'Error', 'status': 'No se pudo obtener headers', 'impact': str(e)}]
    results = []
    # Content-Security-Policy
    csp = headers.get('Content-Security-Policy')
    if not csp:
        results.append({'name': 'Content-Security-Policy', 'status': '❌ Ausente', 'impact': 'Riesgo de XSS'})
    else:
        if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
            results.append({'name': 'Content-Security-Policy', 'status': '⚠️ Débil', 'impact': 'Protección limitada contra XSS'})
        else:
            results.append({'name': 'Content-Security-Policy', 'status': '✔ Presente', 'impact': 'Protege contra XSS'})
    # Strict-Transport-Security
    hsts = headers.get('Strict-Transport-Security')
    if not hsts:
        results.append({'name': 'Strict-Transport-Security', 'status': '❌ Ausente', 'impact': 'Riesgo de downgrade a HTTP'})
    else:
        results.append({'name': 'Strict-Transport-Security', 'status': '✔ Presente', 'impact': 'Protege contra downgrade'})
    # X-Frame-Options
    xfo = headers.get('X-Frame-Options')
    if not xfo:
        results.append({'name': 'X-Frame-Options', 'status': '❌ Ausente', 'impact': 'Riesgo de clickjacking'})
    else:
        results.append({'name': 'X-Frame-Options', 'status': '✔ Presente', 'impact': 'Protege contra clickjacking'})
    # X-Content-Type-Options
    xcto = headers.get('X-Content-Type-Options')
    if not xcto:
        results.append({'name': 'X-Content-Type-Options', 'status': '❌ Ausente', 'impact': 'Riesgo de ejecución de contenido malicioso'})
    else:
        results.append({'name': 'X-Content-Type-Options', 'status': '✔ Presente', 'impact': 'Protege contra ejecución de contenido malicioso'})
    # Referrer-Policy
    refpol = headers.get('Referrer-Policy')
    if not refpol:
        results.append({'name': 'Referrer-Policy', 'status': '❌ Ausente', 'impact': 'Riesgo de fuga de información de referencia'})
    else:
        results.append({'name': 'Referrer-Policy', 'status': '✔ Presente', 'impact': 'Protege la privacidad del usuario'})
    # Permissions-Policy
    ppol = headers.get('Permissions-Policy')
    if not ppol:
        results.append({'name': 'Permissions-Policy', 'status': '❌ Ausente', 'impact': 'Riesgo de abuso de APIs del navegador'})
    else:
        results.append({'name': 'Permissions-Policy', 'status': '✔ Presente', 'impact': 'Restringe acceso a APIs del navegador'})
    return results
