from flask import Flask, request, jsonify
from modules import security_headers, cookies, https_cert, info_exposed, scoring

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL requerida'}), 400
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

if __name__ == '__main__':
    app.run(debug=False)
