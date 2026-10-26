"""
Unit test suite for SecureScan Flask Backend and Risk Prioritization Engine.
"""

import os
import json
import unittest
from app import app
from models import init_db, get_scan, get_scan_findings


class SecureScanTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        init_db()

    def test_pages_served(self):
        for page in ["/", "/index.html", "/scan.html", "/scanning.html", "/results.html", "/report.html"]:
            res = self.client.get(page)
            self.assertEqual(res.status_code, 200, f"Page {page} returned status {res.status_code}")
            self.assertIn(b"SecureScan", res.data)

    def test_scan_api_with_uploaded_file(self):
        import io
        custom_zap = {
            "site": [{
                "@name": "http://custom-lab.internal",
                "alerts": [{
                    "pluginId": "40018",
                    "alert": "SQL Injection",
                    "riskcode": "3",
                    "confidence": "3",
                    "desc": "Custom SQLi detected.",
                    "cweid": "89",
                    "instances": [{"uri": "http://custom-lab.internal/item?id=1", "param": "id"}]
                }]
            }]
        }
        file_bytes = io.BytesIO(json.dumps(custom_zap).encode("utf-8"))
        res = self.client.post(
            "/api/scan",
            data={
                "target_url": "http://custom-lab.internal",
                "consent": "1",
                "zap_file": (file_bytes, "custom_zap.json")
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["total_findings"], 1)
        self.assertEqual(data["critical_count"], 1)

    def test_remediation_endpoint(self):
        res = self.client.get("/api/remediation/sql_injection")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("SQL Injection", data["title"])
        self.assertIn("secure_code_example", data)
        res = self.client.post("/api/scan", data={"target_url": "https://lab.local", "consent": "0"})
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertFalse(data["success"])

    def test_scan_api_with_sample_report(self):
        # Trigger scan with sample report
        res = self.client.post("/api/scan", data={"target_url": "http://lab-target.local", "consent": "1"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("scan_id", data)
        self.assertGreater(data["total_findings"], 0)
        scan_id = data["scan_id"]

        # Check status endpoint
        status_res = self.client.get(f"/api/scan/{scan_id}/status")
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.get_json()
        self.assertEqual(status_data["status"], "completed")

        # Check summary endpoint
        summary_res = self.client.get(f"/api/scan/{scan_id}/summary")
        self.assertEqual(summary_res.status_code, 200)
        summary_data = summary_res.get_json()
        self.assertEqual(summary_data["target_url"], "http://lab-target.local")
        self.assertIn("chart_data", summary_data)
        self.assertEqual(len(summary_data["chart_data"]["counts"]), 4)

        # Check findings endpoint
        findings_res = self.client.get(f"/api/scan/{scan_id}/findings")
        self.assertEqual(findings_res.status_code, 200)
        findings_data = findings_res.get_json()
        self.assertGreater(len(findings_data["findings"]), 0)
        
        # Verify findings are sorted in descending order of risk_score
        findings = findings_data["findings"]
        risk_scores = [f["risk_score"] for f in findings]
        self.assertEqual(risk_scores, sorted(risk_scores, reverse=True), "Findings are not sorted by priority!")

        # Verify OWASP, CWE, and remediation code example exist on top finding
        top = findings[0]
        self.assertTrue(top["owasp_category"].startswith("A"))
        self.assertTrue(top["cwe_id"].startswith("CWE"))
        self.assertGreater(len(top["remediation_fix"]), 10)
        self.assertGreater(len(top["secure_code_example"]), 0)

        # Check report data endpoint
        report_res = self.client.get(f"/api/scan/{scan_id}/report-data")
        self.assertEqual(report_res.status_code, 200)
        report_data = report_res.get_json()
        self.assertIn("executive_summary", report_data)
        self.assertIn("recommendations", report_data)

        # Check downloadable HTML report export
        export_res = self.client.get(f"/api/scan/{scan_id}/export-html")
        self.assertEqual(export_res.status_code, 200)
        self.assertEqual(export_res.mimetype, "text/html")
        self.assertIn(b"Security Assessment Report", export_res.data)
        self.assertIn(b"Prioritized Vulnerability Matrix", export_res.data)

        print("\nAll SecureScan tests passed successfully!")


if __name__ == "__main__":
    unittest.main()
