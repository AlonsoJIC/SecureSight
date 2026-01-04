import requests

def analyze(url):
    try:
        resp = requests.get(url, timeout=10)
        headers = resp.headers
        text = resp.text
    except Exception as e:
        return [{'name': 'Error', 'status': 'No se pudo obtener información', 'impact': str(e)}]
    results = []
    # Server header
    server = headers.get('Server')
    if server:
        results.append({'name': 'Server', 'status': server, 'impact': 'Expone tecnología del servidor'})
    # X-Powered-By
    powered = headers.get('X-Powered-By')
    if powered:
        results.append({'name': 'X-Powered-By', 'status': powered, 'impact': 'Expone tecnología backend'})
    # Tecnologías detectables
    techs = []
    if 'wp-content' in text:
        techs.append('WordPress')
    if 'Drupal.settings' in text:
        techs.append('Drupal')
    if 'Joomla!' in text:
        techs.append('Joomla')
    if techs:
        results.append({'name': 'Tecnologías detectadas', 'status': ', '.join(techs), 'impact': 'Superficie de ataque identificable'})
    # Errores verbosos
    if 'Exception' in text or 'Traceback' in text or 'Fatal error' in text:
        results.append({'name': 'Errores verbosos', 'status': 'Detectados', 'impact': 'Puede revelar información sensible'})
    return results
