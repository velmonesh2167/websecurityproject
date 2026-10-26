"""
Remediation Knowledge Base for Web Application Security Risk Prioritization.
Provides simple explanations, security impacts, defensive fixes, and copyable secure code examples.
"""

KNOWLEDGE_BASE = {
    "sql_injection": {
        "keywords": ["sql injection", "sqli", "blind sql", "cwe-89", "89"],
        "title": "SQL Injection (SQLi)",
        "cwe_id": "CWE-89",
        "cwe_title": "Improper Neutralization of Special Elements used in an SQL Command",
        "owasp_category": "A03:2021 - Injection",
        "base_impact": 5,
        "base_likelihood": 4,
        "simple_explanation": "SQL Injection occurs when untrusted user input is directly concatenated or interpolated into a database SQL query without prior neutralization or parameter binding. This allows an attacker to manipulate the query structure.",
        "impact": "An attacker can bypass authentication, read or extract sensitive confidential data (credentials, PII, financial records), alter or delete database records, and in severe cases gain administrative control over the underlying database server host.",
        "defensive_fix": (
            "1. Always use parameterized queries (Prepared Statements) with parameterized placeholders (? or :named).\n"
            "2. Utilize reputable Object-Relational Mappers (ORMs) such as SQLAlchemy, Hibernate, or Prisma.\n"
            "3. Enforce the Principle of Least Privilege on database user accounts (read-only where write access is not needed).\n"
            "4. Validate and whitelist numeric IDs and input types before processing."
        ),
        "secure_code_example": """# Python / SQLite Secure Example
import sqlite3

def get_user_profile(user_id):
    # SECURE: Using parameterized queries (prepared statements)
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT id, username, email FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

# INSECURE ANTI-PATTERN TO AVOID:
# cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")  # VULNERABLE!"""
    },

    "command_injection": {
        "keywords": ["command injection", "remote code execution", "rce", "os command", "cwe-78", "78"],
        "title": "Remote OS Command Injection",
        "cwe_id": "CWE-78",
        "cwe_title": "Improper Neutralization of Special Elements used in an OS Command",
        "owasp_category": "A03:2021 - Injection",
        "base_impact": 5,
        "base_likelihood": 4,
        "simple_explanation": "Command Injection occurs when user input is passed directly to an operating system shell or system execution function (such as exec(), system(), or shell=True) without proper validation or escaping.",
        "impact": "Attackers can execute arbitrary operating system commands with the privileges of the web application service account, leading to complete server takeover, lateral network movement, ransomware deployment, and sensitive file exfiltration.",
        "defensive_fix": (
            "1. Avoid executing shell commands directly from web applications whenever possible.\n"
            "2. If system operations are necessary, use built-in language APIs rather than shell utilities.\n"
            "3. When invoking external binaries, pass arguments as discrete array tokens (e.g. subprocess.run(['ping', '-c', '1', ip])) with shell=False.\n"
            "4. Validate input strictly against a regex whitelist (e.g., valid IP format ^\\d{1,3}(\\.\\d{1,3}){3}$)."
        ),
        "secure_code_example": """# Python Subprocess Secure Example
import subprocess
import ipaddress

def ping_host(host_ip):
    # SECURE: Validate format as genuine IP address
    try:
        validated_ip = str(ipaddress.ip_address(host_ip))
    except ValueError:
        raise ValueError("Invalid IP address format")

    # SECURE: Pass arguments as a list with shell=False (prevents command chaining)
    result = subprocess.run(
        ["ping", "-c", "2", validated_ip],
        capture_output=True,
        text=True,
        check=False,
        shell=False # Never use shell=True with untrusted input!
    )
    return result.stdout"""
    },

    "xss": {
        "keywords": ["cross-site scripting", "xss", "reflected xss", "stored xss", "dom xss", "cwe-79", "79"],
        "title": "Cross-Site Scripting (XSS)",
        "cwe_id": "CWE-79",
        "cwe_title": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "owasp_category": "A03:2021 - Injection",
        "base_impact": 4,
        "base_likelihood": 4,
        "simple_explanation": "Cross-Site Scripting (XSS) occurs when an application receives untrusted data and includes it in a web page response without contextual encoding or validation, causing the victim's browser to execute malicious client-side JavaScript.",
        "impact": "Attackers can hijack user sessions, steal session cookies or auth tokens, impersonate users, deface website content, log keystrokes, and redirect victims to malicious phishing pages.",
        "defensive_fix": (
            "1. Contextually encode all dynamic data before rendering in HTML bodies, attributes, JavaScript blocks, or URLs (use html.escape or modern templating engines with auto-escaping enabled).\n"
            "2. Implement a Content Security Policy (CSP) with strict script-src directives.\n"
            "3. Set HttpOnly flag on session cookies to block JavaScript access.\n"
            "4. Sanitize rich HTML using trusted sanitizers like DOMPurify."
        ),
        "secure_code_example": """<!-- Jinja2 / Flask Secure Template Rendering -->
<!-- SECURE: Jinja2 automatically HTML-escapes output inside {{ ... }} -->
<div class="user-profile">
    <h2>Welcome, {{ username }}</h2>
    <p>Bio: {{ user_bio }}</p>
</div>

<!-- JavaScript DOM insertion Secure Pattern -->
<script>
// SECURE: Use textContent instead of innerHTML
const usernameEl = document.getElementById('usernameDisplay');
usernameEl.textContent = untrustedUserData; // Prevents script execution!

// INSECURE TO AVOID:
// usernameEl.innerHTML = untrustedUserData; // VULNERABLE TO XSS!
</script>"""
    },

    "csrf": {
        "keywords": ["csrf", "anti-csrf", "cross-site request forgery", "cwe-352", "352"],
        "title": "Cross-Site Request Forgery (CSRF)",
        "cwe_id": "CWE-352",
        "cwe_title": "Cross-Site Request Forgery (CSRF)",
        "owasp_category": "A01:2021 - Broken Access Control",
        "base_impact": 3,
        "base_likelihood": 3,
        "simple_explanation": "CSRF tricks a victim into executing unwanted actions on a web application in which they are currently authenticated, exploiting the browser's automatic sending of session cookies with cross-site requests.",
        "impact": "Unauthorized fund transfers, password or email changes leading to account takeover, and modifications to user settings performed without the user's explicit consent.",
        "defensive_fix": (
            "1. Use synchronizer Anti-CSRF tokens for all state-changing HTTP requests (POST, PUT, DELETE, PATCH).\n"
            "2. Set SameSite=Lax or SameSite=Strict on all authentication and session cookies.\n"
            "3. Enforce custom request headers (e.g., X-Requested-With) on AJAX endpoints.\n"
            "4. Verify Origin and Referer headers on incoming sensitive requests."
        ),
        "secure_code_example": """# Flask-WTF CSRF Protection Example
from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-random-key-here'
csrf = CSRFProtect(app)  # Automatically validates CSRF token on all POST requests

# HTML Form Implementation:
'''
<form method="POST" action="/update-email">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <input type="email" name="new_email" required />
    <button type="submit">Update Email</button>
</form>
'''"""
    },

    "csp_missing": {
        "keywords": ["content security policy", "csp", "cwe-693", "693", "security header", "csp header"],
        "title": "Missing Content Security Policy (CSP)",
        "cwe_id": "CWE-693",
        "cwe_title": "Protection Mechanism Failure",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "base_impact": 2,
        "base_likelihood": 4,
        "simple_explanation": "Content Security Policy (CSP) is an HTTP header that allows site operators to restrict the resources (such as JavaScript, CSS, Images, Frames) that the browser is allowed to load for a given page.",
        "impact": "Absence of CSP removes a critical second line of defense against Cross-Site Scripting (XSS), clickjacking, and data injection attacks.",
        "defensive_fix": (
            "1. Define a Content-Security-Policy HTTP header on all server responses.\n"
            "2. Set default-src 'self' to block external resource loading by default.\n"
            "3. Disallow 'unsafe-inline' and 'unsafe-eval' for scripts.\n"
            "4. Restrict framing with frame-ancestors 'none' or 'self'."
        ),
        "secure_code_example": """# Python / Flask Secure Headers Middleware
@app.after_request
def apply_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response"""
    },

    "insecure_cookie": {
        "keywords": ["httponly", "cookie", "samesite", "cwe-1004", "1004", "cwe-614", "614"],
        "title": "Insecure Cookie Configuration (Missing HttpOnly / Secure)",
        "cwe_id": "CWE-1004",
        "cwe_title": "Sensitive Cookie Without 'HttpOnly' Flag",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "base_impact": 2,
        "base_likelihood": 3,
        "simple_explanation": "Cookies carrying session tokens or credentials lacking HttpOnly, Secure, or SameSite attributes can be accessed by client-side JavaScript or transmitted over unencrypted HTTP channels.",
        "impact": "If an XSS vulnerability exists anywhere on the site, malicious JavaScript can steal the session cookie immediately via document.cookie and hijack user accounts.",
        "defensive_fix": (
            "1. Set HttpOnly=True on all session cookies to prevent access from JavaScript.\n"
            "2. Set Secure=True so the cookie is only transmitted over HTTPS connections.\n"
            "3. Set SameSite=Lax (or Strict) to provide default protection against CSRF.\n"
            "4. Set an appropriate expiration time and clear cookies upon logout."
        ),
        "secure_code_example": """# Flask Secure Cookie Configuration
from flask import Flask, make_response

app = Flask(__name__)

# Global session cookie security settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # Requires HTTPS in production
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800  # 30-minute session expiry
)

@app.route('/login', methods=['POST'])
def login():
    resp = make_response({"status": "logged_in"})
    # Setting an individual cookie securely:
    resp.set_cookie(
        'session_token',
        'auth_token_value_here',
        httponly=True,
        secure=True,
        samesite='Lax',
        max_age=3600
    )
    return resp"""
    },

    "info_disclosure": {
        "keywords": ["error disclosure", "information disclosure", "stack trace", "cwe-200", "200", "debug"],
        "title": "Information Disclosure & Stack Trace Exposure",
        "cwe_id": "CWE-200",
        "cwe_title": "Exposure of Sensitive Information to an Unauthorized Actor",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "base_impact": 2,
        "base_likelihood": 3,
        "simple_explanation": "The web application outputs sensitive technical debugging data, such as database error codes, SQL syntax messages, software version banners, or stack traces directly in client responses.",
        "impact": "Adversaries gain precise reconnaissance details on database engines, framework versions, file system structure, and internal dependencies, accelerating targeted exploit attempts.",
        "defensive_fix": (
            "1. Turn off debug mode in production (DEBUG = False).\n"
            "2. Implement custom global error handlers for HTTP 404, 500, and unhandled exceptions.\n"
            "3. Display neutral, user-friendly error messages to clients.\n"
            "4. Write detailed debugging traces to secure, restricted server-side logs only."
        ),
        "secure_code_example": """# Flask Production Error Handling
from flask import Flask, render_template, jsonify
import logging

app = Flask(__name__)
app.config['DEBUG'] = False  # NEVER True in production!

# Set up server-side logging
logging.basicConfig(filename='secure_error.log', level=logging.ERROR)

@app.errorhandler(500)
def internal_error(error):
    # Log the real error on the server securely:
    logging.error(f"Internal server error: {error}")
    # Return a generic message without exposing stack traces to the user:
    return jsonify({
        "error": "An unexpected error occurred. Please contact system support."
    }), 500"""
    },

    "path_traversal": {
        "keywords": ["directory traversal", "path traversal", "cwe-22", "22"],
        "title": "Path Traversal / Arbitrary File Read",
        "cwe_id": "CWE-22",
        "cwe_title": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "owasp_category": "A01:2021 - Broken Access Control",
        "base_impact": 4,
        "base_likelihood": 3,
        "simple_explanation": "An application accepts user-supplied filenames or paths and uses them to access files on the filesystem without sanitizing directory dot-dot-slash sequence (../) characters.",
        "impact": "Attackers can read sensitive files outside the web root, including configuration files, environment variables (.env), source code, /etc/passwd, and private keys.",
        "defensive_fix": (
            "1. Never pass raw user input into file system path functions.\n"
            "2. Use secure path resolution (e.g. werkzeug.utils.secure_filename or os.path.realpath checking).\n"
            "3. Ensure the resolved real path begins strictly with the allowed base directory.\n"
            "4. Store files using synthetic GUID identifiers rather than user-supplied filenames."
        ),
        "secure_code_example": """import os
from werkzeug.utils import secure_filename

SAFE_BASE_DIR = os.path.abspath("/var/www/uploads")

def get_uploaded_file(untrusted_filename):
    # Sanitize the filename to strip traversal sequences (../)
    filename = secure_filename(untrusted_filename)
    full_path = os.path.abspath(os.path.join(SAFE_BASE_DIR, filename))
    
    # Ensure the resolved path remains inside the base directory
    if not full_path.startswith(SAFE_BASE_DIR):
        raise PermissionError("Access denied: path traversal attempt detected")
        
    with open(full_path, "rb") as f:
        return f.read()"""
    }
}


def lookup_remediation(alert_name="", cwe_id="", zap_risk=""):
    """
    Looks up a knowledge base entry matching an alert name, CWE ID, or keywords.
    Provides a standardized fallback if no direct keyword match exists.
    """
    clean_alert = str(alert_name or "").lower().strip()
    search_terms = f"{alert_name} {cwe_id}".lower()
    
    # Check exact key first
    if clean_alert in KNOWLEDGE_BASE:
        return KNOWLEDGE_BASE[clean_alert]

    for key, data in KNOWLEDGE_BASE.items():
        if key in clean_alert or clean_alert in key:
            return data
        for keyword in data["keywords"]:
            if keyword in search_terms:
                return data

    # Generic fallback based on ZAP risk and CWE
    clean_cwe = cwe_id if cwe_id and cwe_id != "0" else "CWE-General"
    return {
        "title": alert_name or "Web Application Security Weakness",
        "cwe_id": clean_cwe,
        "cwe_title": "Identified Security Configuration or Input Flaw",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "base_impact": 2,
        "base_likelihood": 2,
        "simple_explanation": (
            f"The scanner identified an issue related to '{alert_name}'. "
            "Untrusted inputs or suboptimal security configurations may expose functionality to unauthorized access."
        ),
        "impact": "May allow malicious actors to gather reconnaissance data or trigger unexpected system behavior.",
        "defensive_fix": (
            "1. Review input validation and output encoding for affected parameters.\n"
            "2. Verify least-privilege configurations and disable unused endpoints.\n"
            "3. Follow the OWASP Application Security Verification Standard (ASVS)."
        ),
        "secure_code_example": """# General Defensive Pattern
# 1. Validate all inputs against strict schema / whitelist
# 2. Sanitize and escape all outputs
# 3. Implement defensive HTTP headers (CSP, HSTS, X-Frame-Options)"""
    }
