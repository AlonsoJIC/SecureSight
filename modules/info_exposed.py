import requests

def analyze(url):
    try:
        resp = requests.get(url, timeout=10)
        headers = resp.headers
        text = resp.text
    except Exception as e:
        return [{'name': 'Error', 'status': 'Could not retrieve information', 'impact': str(e)}]
    results = []
    # Server header
    server = headers.get('Server')
    if server:
        results.append({'name': 'Server', 'status': server, 'impact': 'Server technology exposed'})
    # X-Powered-By
    powered = headers.get('X-Powered-By')
    if powered:
        results.append({'name': 'X-Powered-By', 'status': powered, 'impact': 'Backend technology exposed'})
    # Detectable technologies
    techs = []
    if 'wp-content' in text:
        techs.append('WordPress')
    if 'Drupal.settings' in text:
        techs.append('Drupal')
    if 'Joomla!' in text:
        techs.append('Joomla')
    if techs:
        results.append({'name': 'Detected technologies', 'status': ', '.join(techs), 'impact': 'Identifiable attack surface'})
    # Verbose errors
    if 'Exception' in text or 'Traceback' in text or 'Fatal error' in text:
        results.append({'name': 'Verbose errors', 'status': 'Detected', 'impact': 'May reveal sensitive information'})
    return results
