def calculate(headers, cookies, https, info):
    score = 100
    # Headers
    for h in headers:
        if h['name'] == 'Content-Security-Policy' and ('Ausente' in h['status'] or 'Absent' in h['status']):
            score -= 20
        if h['name'] == 'Strict-Transport-Security' and ('Ausente' in h['status'] or 'Absent' in h['status']):
            score -= 10
        if h['name'] == 'X-Frame-Options' and ('Ausente' in h['status'] or 'Absent' in h['status']):
            score -= 10
        if h['name'] == 'X-Content-Type-Options' and ('Ausente' in h['status'] or 'Absent' in h['status']):
            score -= 10
        if h['name'] == 'Referrer-Policy' and ('Ausente' in h['status'] or 'Absent' in h['status']):
            score -= 5
        if h['name'] == 'Permissions-Policy' and ('Ausente' in h['status'] or 'Absent' in h['status']):
            score -= 5
    # Cookies
    for c in cookies:
        if 'Not Secure' in c['status']:
            score -= 10
        if 'Not HttpOnly' in c['status']:
            score -= 10
        if 'No SameSite' in c['status']:
            score -= 5
    # HTTPS
    for h in https:
        if h['name'] == 'HTTPS' and ('No activo' in h['status'] or 'Inactive' in h['status']):
            score -= 30
    # Info expuesta
    for i in info:
        if i['name'] in ['Server', 'X-Powered-By', 'Detected technologies']:
            score -= 5
        if i['name'] == 'Verbose errors':
            score -= 10
    # Classification
    if score >= 80:
        status = 'Secure'
    elif score >= 60:
        status = 'Needs improvement'
    else:
        status = 'High risk'
    return {'value': max(score, 0), 'status': status}
