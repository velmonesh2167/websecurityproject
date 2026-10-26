"""
SecureScan - Web Application Security Risk Prioritization and Reporting System
Flask Backend Application.
"""

import os
import json
import time
from flask import Flask, request, jsonify, send_from_directory, render_template_string, Response
from models import (
    init_db, create_scan, update_scan_progress, complete_scan,
    save_findings, get_scan, get_latest_scan, get_scan_findings
)
from analyzer import process_zap_report
from knowledge_base import KNOWLEDGE_BASE, lookup_remediation

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_ZAP_PATH = os.path.join(BASE_DIR, "sample_zap_report.json")

app = Flask(__name__, static_folder=".", static_url_path="")
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

# Initialize SQLite database on startup
init_db()


# -------------------------------------------------------------------------
# Static Page Routes (Serves existing frontend files unmodified)
# -------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/<path:filename>")
def serve_static_page(filename):
    if os.path.exists(os.path.join(BASE_DIR, filename)):
        return send_from_directory(BASE_DIR, filename)
    return jsonify({"error": "File not found"}), 404


# -------------------------------------------------------------------------
# API Endpoints
# -------------------------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def start_scan_api():
    """
    Accepts target URL, authorization consent checkbox, and an uploaded OWASP ZAP JSON report.
    Performs risk prioritization (Impact x Likelihood), OWASP/CWE mapping, and stores results in SQLite.
    """
    # Extract target URL and authorization consent cleanly
    if request.is_json and request.json:
        target_url = request.json.get("target_url", "")
        consent_val = request.json.get("consent", "")
    else:
        target_url = request.form.get("target_url", "")
        consent_val = request.form.get("consent", "")

    if not target_url:
        return jsonify({"success": False, "error": "Target URL is required."}), 400

    if str(consent_val).lower() not in ["1", "true", "yes", "on"]:
        return jsonify({
            "success": False,
            "error": "Authorization consent checkbox must be confirmed (Authorized testing/lab use only)."
        }), 403

    # Check for uploaded ZAP JSON file
    zap_data = None
    if "zap_file" in request.files:
        file = request.files["zap_file"]
        if file and file.filename != "":
            try:
                zap_data = json.load(file)
            except Exception as e:
                return jsonify({"success": False, "error": f"Invalid JSON report format: {str(e)}"}), 400

    # If no file uploaded, check if raw json was passed in body
    if zap_data is None and request.is_json and "zap_data" in request.json:
        zap_data = request.json["zap_data"]

    # Fallback: load bundled sample ZAP report
    if zap_data is None:
        if os.path.exists(SAMPLE_ZAP_PATH):
            with open(SAMPLE_ZAP_PATH, "r", encoding="utf-8") as f:
                zap_data = json.load(f)
        else:
            zap_data = {"alerts": []}

    # 1. Create scan entry in SQLite
    scan_id = create_scan(target_url=target_url, consent=1)

    # 2. Process and prioritize findings
    findings, summary_stats = process_zap_report(zap_data, default_target_url=target_url)

    # 3. Store findings into SQLite
    save_findings(scan_id, findings)

    # 4. Finalize scan record with summary statistics
    complete_scan(scan_id, summary_stats)

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "target_url": target_url,
        "status": "completed",
        "total_findings": summary_stats["total_findings"],
        "critical_count": summary_stats["critical_count"],
        "high_count": summary_stats["high_count"],
        "medium_count": summary_stats["medium_count"],
        "low_count": summary_stats["low_count"],
        "overall_risk_level": summary_stats["overall_risk_level"]
    })


@app.route("/api/scan/<int:scan_id>/status", methods=["GET"])
def get_scan_status(scan_id):
    """
    Returns the scan progress and pipeline stage for scanning.html polling.
    """
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "scan_id": scan["id"],
        "target_url": scan["target_url"],
        "status": scan["status"],
        "progress": scan["progress"],
        "current_step": scan["current_step"],
        "total_findings": scan["total_findings"],
        "overall_risk_level": scan["overall_risk_level"]
    })


@app.route("/api/scan/<int:scan_id>/summary", methods=["GET"])
def get_scan_summary_api(scan_id):
    """
    Returns summary metrics, severity counts, and chart dataset for results.html.
    """
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    chart_data = {
        "labels": ["Critical", "High", "Medium", "Low"],
        "counts": [
            scan["critical_count"],
            scan["high_count"],
            scan["medium_count"],
            scan["low_count"]
        ],
        "colors": ["#dc2626", "#ea580c", "#d97706", "#16a34a"]
    }

    return jsonify({
        "scan_id": scan["id"],
        "target_url": scan["target_url"],
        "created_at": scan["created_at"],
        "total_findings": scan["total_findings"],
        "critical_count": scan["critical_count"],
        "high_count": scan["high_count"],
        "medium_count": scan["medium_count"],
        "low_count": scan["low_count"],
        "overall_risk_score": scan["overall_risk_score"],
        "overall_risk_level": scan["overall_risk_level"],
        "chart_data": chart_data
    })


@app.route("/api/scan/<int:scan_id>/findings", methods=["GET"])
def get_scan_findings_api(scan_id):
    """
    Returns all findings for a given scan, sorted by priority ranking.
    """
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = get_scan_findings(scan_id)
    return jsonify({
        "scan_id": scan["id"],
        "target_url": scan["target_url"],
        "total": len(findings),
        "findings": findings
    })


@app.route("/api/scans/latest", methods=["GET"])
def get_latest_scan_api():
    """Returns the most recent scan ID and metadata."""
    scan = get_latest_scan()
    if not scan:
        return jsonify({"error": "No scans available"}), 404
    return jsonify(scan)


@app.route("/api/remediation/<topic>", methods=["GET"])
def get_remediation_api(topic):
    """
    Fetches explanation, impact, defensive remediation, and code examples from the Knowledge Base.
    """
    rem = lookup_remediation(alert_name=topic, cwe_id=topic)
    return jsonify(rem)


@app.route("/api/scan/<int:scan_id>/report-data", methods=["GET"])
def get_report_data(scan_id):
    """
    Returns combined data required to render the full security report.
    """
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = get_scan_findings(scan_id)
    
    # Generate executive summary points
    executive_summary = (
        f"A targeted web application security assessment was conducted for '{scan['target_url']}' "
        f"on {scan['created_at']}. A total of {scan['total_findings']} vulnerability findings were identified "
        f"and evaluated using the Impact x Likelihood risk prioritization matrix. "
        f"The overall security risk posture is rated as '{scan['overall_risk_level']}'. "
        f"Immediate defensive remediation is recommended for all critical and high severity findings."
    )

    recommendations = [
        "1. Prioritize immediate remediation of Critical vulnerabilities (e.g. SQL Injection, Remote Command Execution).",
        "2. Neutralize High severity issues through parameterized APIs, output encoding, and strong access controls.",
        "3. Configure modern defense-in-depth HTTP security headers (Content-Security-Policy, HSTS, X-Frame-Options).",
        "4. Enforce HttpOnly, Secure, and SameSite flags on all session and authentication cookies.",
        "5. Disable debug modes, suppress verbose error messages, and implement centralized exception handling.",
        "6. Conduct recurring verification scans following code deployment in the lab environment."
    ]

    return jsonify({
        "scan": scan,
        "executive_summary": executive_summary,
        "recommendations": recommendations,
        "findings": findings
    })


@app.route("/api/scan/<int:scan_id>/export-html", methods=["GET"])
def export_html_report(scan_id):
    """
    Generates and returns a downloadable, standalone, self-contained HTML report.
    """
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = get_scan_findings(scan_id)

    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {{ scan.target_url }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #1e293b; margin: 0; padding: 40px 20px; line-height: 1.6; }
        .container { max-width: 960px; margin: auto; background: #ffffff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); padding: 40px; }
        .header { text-align: center; border-bottom: 2px solid #e2e8f0; padding-bottom: 25px; margin-bottom: 30px; }
        .header h1 { margin: 0 0 10px; color: #0f172a; font-size: 28px; }
        .header p { margin: 0; color: #64748b; font-size: 15px; }
        .badge { display: inline-block; padding: 6px 14px; border-radius: 9999px; font-weight: bold; font-size: 13px; text-transform: uppercase; }
        .badge-critical { background: #fee2e2; color: #b91c1c; border: 1px solid #f87171; }
        .badge-high { background: #ffedd5; color: #c2410c; border: 1px solid #fb923c; }
        .badge-medium { background: #fef3c7; color: #b45309; border: 1px solid #fcd34d; }
        .badge-low { background: #dcfce7; color: #15803d; border: 1px solid #86efac; }
        .section-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 25px; }
        .section-box h2 { margin-top: 0; font-size: 18px; color: #0f172a; border-bottom: 1px solid #cbd5e1; padding-bottom: 8px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 15px; }
        .stat-card { background: #fff; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #e2e8f0; }
        .stat-card strong { display: block; font-size: 24px; margin-bottom: 5px; }
        .finding-item { border: 1px solid #e2e8f0; border-left: 5px solid #3b82f6; border-radius: 6px; padding: 18px; margin-bottom: 20px; background: #ffffff; }
        .finding-item.Critical { border-left-color: #dc2626; }
        .finding-item.High { border-left-color: #ea580c; }
        .finding-item.Medium { border-left-color: #d97706; }
        .finding-item.Low { border-left-color: #16a34a; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .finding-title { font-size: 18px; font-weight: bold; color: #0f172a; }
        .code-box { background: #0f172a; color: #f8fafc; padding: 14px; border-radius: 6px; font-family: Consolas, Monaco, monospace; font-size: 13px; overflow-x: auto; margin-top: 10px; }
        .disclaimer { font-size: 12px; color: #64748b; text-align: center; margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #071e3d; color: #ffffff; font-weight: 600; }
        @media print { body { padding: 0; background: #fff; } .container { box-shadow: none; border-radius: 0; max-width: 100%; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Web Application Security Assessment Report</h1>
            <p>Risk Prioritization and Remediation Analysis (Lab Use Only)</p>
            <p style="margin-top: 8px;"><strong>Target:</strong> {{ scan.target_url }} | <strong>Date:</strong> {{ scan.created_at }}</p>
        </div>

        <div class="section-box">
            <h2>Executive Summary</h2>
            <p>
                A comprehensive security assessment was conducted for target <strong>{{ scan.target_url }}</strong>.
                The system analyzed scanner alerts, mapped vulnerabilities against <strong>OWASP Top 10 (2021)</strong> and <strong>CWE standards</strong>,
                and applied a quantitative <strong>Risk = Impact &times; Likelihood</strong> prioritization methodology.
            </p>
            <p>
                Overall Risk Assessment: <strong>{{ scan.overall_risk_level }}</strong> (Average Risk Score: {{ scan.overall_risk_score }}/25).
            </p>

            <div class="stats-grid">
                <div class="stat-card">
                    <strong style="color: #dc2626;">{{ scan.critical_count }}</strong>
                    <span>Critical</span>
                </div>
                <div class="stat-card">
                    <strong style="color: #ea580c;">{{ scan.high_count }}</strong>
                    <span>High</span>
                </div>
                <div class="stat-card">
                    <strong style="color: #d97706;">{{ scan.medium_count }}</strong>
                    <span>Medium</span>
                </div>
                <div class="stat-card">
                    <strong style="color: #16a34a;">{{ scan.low_count }}</strong>
                    <span>Low</span>
                </div>
            </div>
        </div>

        <div class="section-box">
            <h2>Prioritized Vulnerability Matrix</h2>
            <table>
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Vulnerability</th>
                        <th>OWASP Top 10</th>
                        <th>CWE</th>
                        <th>Impact</th>
                        <th>Likelihood</th>
                        <th>Risk Score</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {% for f in findings %}
                    <tr>
                        <td><strong>#{{ f.priority_rank }}</strong></td>
                        <td>{{ f.alert_name }}</td>
                        <td>{{ f.owasp_category.split(' - ')[0] if ' - ' in f.owasp_category else f.owasp_category }}</td>
                        <td>{{ f.cwe_id }}</td>
                        <td>{{ f.impact }}/5</td>
                        <td>{{ f.likelihood }}/5</td>
                        <td><strong>{{ f.risk_score }}</strong></td>
                        <td><span class="badge badge-{{ f.severity.lower() }}">{{ f.severity }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="section-box">
            <h2>Remediation Knowledge Base & Defensive Fixes</h2>
            {% for f in findings %}
            <div class="finding-item {{ f.severity }}">
                <div class="finding-header">
                    <span class="finding-title">#{{ f.priority_rank }}. {{ f.alert_name }}</span>
                    <span class="badge badge-{{ f.severity.lower() }}">{{ f.severity }} (Score: {{ f.risk_score }}/25)</span>
                </div>
                <p><strong>OWASP Category:</strong> {{ f.owasp_category }} | <strong>CWE:</strong> {{ f.cwe_id }}: {{ f.cwe_title }}</p>
                {% if f.url %}<p><strong>Target Endpoint:</strong> <code>{{ f.url }}</code> {% if f.param %}(Param: <code>{{ f.param }}</code>){% endif %}</p>{% endif %}
                <p><strong>Explanation:</strong> {{ f.remediation_summary }}</p>
                <p><strong>Security Impact:</strong> {{ f.remediation_impact }}</p>
                <p><strong>Defensive Remediation Steps:</strong></p>
                <div style="white-space: pre-line; background: #f1f5f9; padding: 10px; border-radius: 6px; margin-bottom: 10px;">{{ f.remediation_fix }}</div>
                {% if f.secure_code_example %}
                <p><strong>Secure Implementation Code Example:</strong></p>
                <pre class="code-box"><code>{{ f.secure_code_example }}</code></pre>
                {% endif %}
            </div>
            {% endfor %}
        </div>

        <div class="section-box">
            <h2>Recommended Remediation Actions</h2>
            <ol>
                <li>Immediately isolate and fix all Critical severity issues using parameterized statements and input validation.</li>
                <li>Address High severity items before pushing features to production environments.</li>
                <li>Implement defense-in-depth security headers (Content Security Policy, X-Frame-Options, HSTS).</li>
                <li>Audit and harden session cookies with HttpOnly, Secure, and SameSite attributes.</li>
                <li>Establish recurring automated security scanning as part of the software development lifecycle.</li>
            </ol>
        </div>

        <div class="disclaimer">
            <p><strong>LAB USE DISCLAIMER:</strong> This report is generated solely for academic, research, and authorized lab testing. Only test web applications that you own or have explicit written authorization to test.</p>
            <p>© 2026 SecureScan | Web Application Security Risk Prioritization and Reporting System</p>
        </div>
    </div>
</body>
</html>"""

    rendered_html = render_template_string(html_template, scan=scan, findings=findings)
    filename = f"Security_Report_{scan['id']}_{int(time.time())}.html"

    return Response(
        rendered_html,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# -------------------------------------------------------------------------
# Run Application
# -------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting SecureScan Backend Server on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
