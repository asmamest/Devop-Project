from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from prometheus_client import Counter, Histogram, generate_latest
from app.scanner import APISecurityScanner
import time

app = Flask(__name__)
CORS(app)

scanner = APISecurityScanner()

# Metrics Prometheus
SCAN_COUNT = Counter("scan_total", "Total number of scans")
SCAN_LATENCY = Histogram("scan_latency_seconds", "Scan duration in seconds")

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    data = request.json
    url = data.get('url')
    params = data.get('params', {})

    if not url:
        return jsonify({"error": "URL required"}), 400

    SCAN_COUNT.inc()
    start_time = time.time()
    results = scanner.scan(url, params)
    SCAN_LATENCY.observe(time.time() - start_time)

    return jsonify(results)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "service": "API Security Scanner"})

@app.route("/metrics", methods=["GET"])
def metrics():
    return Response(generate_latest(), mimetype="text/plain")

if __name__ == '__main__':
    app.run(debug=True, port=5000)
