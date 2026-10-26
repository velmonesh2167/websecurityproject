# Web Application Security Risk Prioritization and Reporting System

An intelligent web application vulnerability prioritization and reporting platform designed for university laboratory use and authorized security assessments.

The system ingests security scanner outputs (specifically OWASP ZAP JSON reports), maps findings to **OWASP Top 10 (2021)** categories and **Common Weakness Enumerations (CWE)**, computes a quantitative risk score using the formula $\text{Risk} = \text{Impact} \times \text{Likelihood}$, classifies severity into Critical/High/Medium/Low, sorts issues in descending order of priority, and generates executive and developer-ready security reports with copyable remediation code examples.

---

## Features

- **Ingestion & Parsing:** Seamlessly processes standard OWASP ZAP JSON vulnerability scan exports without executing destructive live attack code.
- **Risk Prioritization Engine:**
  - $\text{Risk Score} = \text{Impact} (1\text{–}5) \times \text{Likelihood} (1\text{–}5)$, yielding a 1–25 quantitative prioritization index.
  - Automatic classification into **Critical** ($\ge 16$), **High** ($11–15$), **Medium** ($6–10$), and **Low** ($1–5$).
- **OWASP Top 10 & CWE Mapping:** Every alert is automatically categorized under the relevant OWASP Top 10 standard and MITRE CWE identifier.
- **Remediation Knowledge Base:** Provides simple explanations, business/technical impacts, defensive mitigation guidance, and copyable secure code implementation snippets (Python, HTML, JS, PHP).
- **Executive Reporting & Export:** Interactive web dashboard plus one-click standalone downloadable HTML report generation for stakeholders.
- **Full SQLite Persistence:** Stores historical scans and vulnerability findings locally.

---

## Project Structure

```text
├── app.py                     # Flask application routes & REST APIs
├── models.py                  # SQLite database schema and persistence layer
├── analyzer.py                # OWASP ZAP parser, risk calculation & OWASP/CWE mapper
├── knowledge_base.py          # Remediation knowledge base with secure code examples
├── sample_zap_report.json     # Sample OWASP ZAP JSON scan report for lab demonstrations
├── requirements.txt           # Python library dependencies
├── README.md                  # Project documentation
├── DISCLAIMER.md              # Academic & authorized lab use disclaimer
├── index.html                 # Landing page
├── scan.html                  # Scan initiation & ZAP file upload page
├── scanning.html              # Real-time scan progress page
├── results.html               # Prioritized findings table & severity chart
├── report.html                # Executive & remediation report page
├── css/
│   └── style.css              # Frontend stylesheets
└── js/
    └── script.js              # Client-side API integration & interactive controller
```

---

## Installation & Setup

### Prerequisites
- Python 3.9+ (Python 3.12 recommended)
- Web browser (Chrome, Firefox, Edge, Safari)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```
By default, the server starts at `http://localhost:5000`.

### 3. Accessing the Application
Open your browser and navigate to:
```text
http://localhost:5000/
```

---

## Workflow Guide

1. **Home (`index.html`):** Click **Start Security Scan** to enter the scanner interface.
2. **Scan Setup (`scan.html`):**
   - Enter your target URL (e.g., `http://localhost:8080` or `https://lab-target.local`).
   - Check the **Authorization Consent** box (verifying you own or have permission to test the system).
   - *(Optional)* Upload an OWASP ZAP JSON export file. If left blank, the application automatically analyzes the included `sample_zap_report.json` containing realistic sample findings (SQLi, Command Injection, XSS, CSRF, CSP Missing, Insecure Cookies, and Information Disclosure).
   - Click **Start Security Scan**.
3. **Scan Execution (`scanning.html`):**
   - Monitors the 4-step pipeline: Connecting, Configuration Check, Vulnerability Analysis, and Report Preparation.
   - Automatically transitions to results upon 100% completion.
4. **Results & Prioritization (`results.html`):**
   - Displays total findings count, Critical/High/Medium/Low distribution, and overall risk badge.
   - Shows interactive severity distribution chart bars.
   - Displays findings table ranked strictly by Risk Score ($\text{Impact} \times \text{Likelihood}$).
   - Click on any finding row to view the **Remediation Knowledge Base Modal** containing simple explanations, security impacts, defensive fixes, and copyable secure code snippets.
5. **Report & Export (`report.html`):**
   - Displays the comprehensive executive assessment report.
   - Click **Print / Save Report** to print or save as PDF via your browser.
   - Click **Download HTML Report** to export a standalone, styled, offline-viewable HTML security report.

---

## API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `GET /` | `GET` | Serves `index.html` |
| `POST /api/scan` | `POST` | Accepts target URL, consent checkbox, and optional ZAP report file |
| `GET /api/scan/<id>/status` | `GET` | Returns scanning progress percentage and current stage |
| `GET /api/scan/<id>/summary` | `GET` | Returns severity counts, overall risk score, and chart dataset |
| `GET /api/scan/<id>/findings` | `GET` | Returns prioritized findings list with CWE, OWASP, and remediation |
| `GET /api/scan/<id>/report-data` | `GET` | Returns full data model for executive report rendering |
| `GET /api/scan/<id>/export-html` | `GET` | Generates and downloads a standalone offline HTML report |
| `GET /api/scans/latest` | `GET` | Fetches the most recent scan metadata |
| `GET /api/remediation/<topic>` | `GET` | Fetches specific remediation entries from the knowledge base |

---

## Risk Calculation Methodology

$$\text{Risk Score} = \text{Impact} \times \text{Likelihood}$$

- **Impact (1 to 5):** Evaluated according to technical severity (5 for RCE/SQLi, 4 for Path Traversal/Stored XSS, 3 for Reflected XSS/CSRF, 2 for Security Headers/Cookies, 1 for Banners).
- **Likelihood (1 to 5):** Calculated based on scanner confidence, existence of injectable parameters, and verified exploit payloads/evidence.
- **Classification Thresholds:**
  - **Critical:** $\text{Score} \ge 16$
  - **High:** $11 \le \text{Score} \le 15$
  - **Medium:** $6 \le \text{Score} \le 10$
  - **Low:** $1 \le \text{Score} \le 5$

---

## Academic Disclaimer
This software is intended strictly for authorized academic research and laboratory environments. Always ensure you have formal authorization before testing any web application.
