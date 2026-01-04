def calculate(headers, cookies, https, info):
    score = 100
    # Headers
    for h in headers:
        if h['name'] == 'Content-Security-Policy' and 'Ausente' in h['status']:
            score -= 20
        if h['name'] == 'Strict-Transport-Security' and 'Ausente' in h['status']:
            score -= 10
        if h['name'] == 'X-Frame-Options' and 'Ausente' in h['status']:
            score -= 10
        if h['name'] == 'X-Content-Type-Options' and 'Ausente' in h['status']:
            score -= 10
        if h['name'] == 'Referrer-Policy' and 'Ausente' in h['status']:
            score -= 5
        if h['name'] == 'Permissions-Policy' and 'Ausente' in h['status']:
            score -= 5
    # Cookies
    for c in cookies:
        if 'No Secure' in c['status']:
            score -= 10
        if 'No HttpOnly' in c['status']:
            score -= 10
        if 'No SameSite' in c['status']:
            score -= 5
    # HTTPS
    for h in https:
        if h['name'] == 'HTTPS' and 'No activo' in h['status']:
            score -= 30
    # Info expuesta
    for i in info:
        if i['name'] in ['Server', 'X-Powered-By', 'Tecnologías detectadas']:
            score -= 5
        if i['name'] == 'Errores verbosos':
            score -= 10
    # Clasificación
    if score >= 80:
        status = 'Seguro'
    elif score >= 60:
        status = 'Mejorable'
    else:
        status = 'Riesgo alto'
    return {'value': max(score, 0), 'status': status}
