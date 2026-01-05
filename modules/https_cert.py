import ssl
import socket
from urllib.parse import urlparse
import requests

def analyze(url):
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    results = []
    try:
        if parsed.scheme != 'https':
            results.append({'name': 'HTTPS', 'status': '❌ Inactive', 'impact': 'The site does not use HTTPS'})
            return results
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                results.append({'name': 'HTTPS', 'status': '✔ Active', 'impact': 'The site uses HTTPS'})
                results.append({'name': 'Certificate', 'status': cert.get('subject', ''), 'impact': ''})
                results.append({'name': 'Expiration', 'status': cert.get('notAfter', ''), 'impact': ''})
    except Exception as e:
        results.append({'name': 'HTTPS/Certificate', 'status': 'Error', 'impact': str(e)})
    return results
