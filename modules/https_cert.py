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
            results.append({'name': 'HTTPS', 'status': '❌ No activo', 'impact': 'El sitio no usa HTTPS'})
            return results
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                results.append({'name': 'HTTPS', 'status': '✔ Activo', 'impact': 'El sitio usa HTTPS'})
                results.append({'name': 'Certificado', 'status': cert.get('subject', ''), 'impact': ''})
                results.append({'name': 'Expiración', 'status': cert.get('notAfter', ''), 'impact': ''})
    except Exception as e:
        results.append({'name': 'HTTPS/Certificado', 'status': 'Error', 'impact': str(e)})
    return results
