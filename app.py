from flask import Flask, request, jsonify
from flasgger import Swagger
from flask_cors import CORS
import validators
from modules import security_headers, cookies, https_cert, info_exposed, scoring

app = Flask(__name__)
Swagger(app)
CORS(app)

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Analiza la seguridad de una URL
    ---
    parameters:
      - name: url
        in: body
        required: true
        schema:
          type: object
          properties:
            url:
              type: string
              example: "https://ejemplo.com"
    responses:
      200:
        description: Reporte de seguridad
        schema:
          type: object
      400:
        description: Error en la petición
        schema:
          type: object
    """
    data = request.get_json()
    url = data.get('url')
    # Validación avanzada de URL
    if not url or not validators.url(url):
        return jsonify({'error': 'URL inválida o ausente'}), 400
    try:
        headers_result = security_headers.analyze(url)
        cookies_result = cookies.analyze(url)
        https_result = https_cert.analyze(url)
        info_result = info_exposed.analyze(url)
        score_result = scoring.calculate(headers_result, cookies_result, https_result, info_result)
        report = {
            'headers': headers_result,
            'cookies': cookies_result,
            'https': https_result,
            'info': info_result,
            'score': score_result
        }
        return jsonify(report)
    except Exception as e:
        return jsonify({'error': f'No se pudo analizar la URL: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=False)
