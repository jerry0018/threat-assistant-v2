from flask import Flask, jsonify, request, send_from_directory, Response
import requests as http
from nvd import lookup
from scanner import run_scan, ScanError
from reports import to_csv, to_pdf

app = Flask(__name__, static_folder="static", static_url_path="/static")


@app.get("/")
def home():
    return send_from_directory("static", "index.html")


@app.post("/api/cve")
def api_cve():
    data = request.get_json(silent=True) or {}
    software = str(data.get("software", "")).strip()[:60]
    version = str(data.get("version", "")).strip()[:30]
    if not software:
        return jsonify(error="Enter a software name, for example Apache HTTP Server."), 400
    try:
        return jsonify(results=lookup(software, version))
    except http.RequestException as e:
        return jsonify(error=f"Could not reach the NVD API: {e}"), 502


@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    if not data.get("authorized"):
        return jsonify(error="Confirm that you own this network or have permission to scan it."), 400
    try:
        return jsonify(hosts=run_scan(data.get("target")))
    except ScanError as e:
        return jsonify(error=str(e)), 400


def _findings():
    items = (request.get_json(silent=True) or {}).get("findings", [])
    return [f for f in items if isinstance(f, dict)][:500]


@app.post("/api/report/csv")
def report_csv():
    return Response(to_csv(_findings()), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=security_report.csv"})


@app.post("/api/report/pdf")
def report_pdf():
    return Response(to_pdf(_findings()), mimetype="application/pdf",
                    headers={"Content-Disposition": "attachment; filename=security_report.pdf"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)  # localhost only
