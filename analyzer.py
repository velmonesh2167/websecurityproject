"""
OWASP ZAP Report Analyzer & Risk Prioritization Engine.
Calculates Risk = Impact x Likelihood, maps to OWASP Top 10 and CWE,
ranks vulnerabilities by priority, and integrates remediation advice.
"""

import json
from knowledge_base import lookup_remediation


OWASP_TOP_10_MAPPING = {
    "A01": ("A01:2021 - Broken Access Control", ["22", "23", "352", "639", "862", "863", "csrf", "traversal", "access control", "idor"]),
    "A02": ("A02:2021 - Cryptographic Failures", ["310", "311", "319", "326", "327", "ssl", "tls", "plaintext", "crypto", "cipher"]),
    "A03": ("A03:2021 - Injection", ["77", "78", "79", "89", "94", "sql", "injection", "command", "xss", "scripting", "ldap", "xpath"]),
    "A04": ("A04:2021 - Insecure Design", ["209", "1021", "clickjacking", "design", "rate limit", "brute force"]),
    "A05": ("A05:2021 - Security Misconfiguration", ["16", "200", "548", "693", "1004", "header", "csp", "directory listing", "debug", "disclosure", "cookie"]),
    "A06": ("A06:2021 - Vulnerable and Outdated Components", ["1104", "outdated", "component", "library", "cve"]),
    "A07": ("A07:2021 - Identification and Authentication Failures", ["287", "384", "613", "614", "session", "auth", "credential", "password"]),
    "A08": ("A08:2021 - Software and Data Integrity Failures", ["494", "502", "deserialization", "integrity", "pipeline"]),
    "A09": ("A09:2021 - Security Logging and Monitoring Failures", ["778", "117", "logging", "audit", "monitoring"]),
    "A10": ("A10:2021 - Server-Side Request Forgery (SSRF)", ["918", "ssrf", "request forgery"])
}


def map_owasp_category(alert_name, cwe_id):
    """Maps alert title and CWE ID to OWASP Top 10 (2021)."""
    search_str = f"{alert_name} {cwe_id}".lower()
    
    for category_code, (label, triggers) in OWASP_TOP_10_MAPPING.items():
        for trigger in triggers:
            if trigger in search_str:
                return label

    return "A05:2021 - Security Misconfiguration"


def parse_zap_alerts(zap_data):
    """
    Extracts raw alert dictionaries from various OWASP ZAP JSON export formats.
    """
    if not zap_data:
        return []

    if isinstance(zap_data, list):
        return zap_data

    if isinstance(zap_data, dict):
        if "site" in zap_data:
            alerts = []
            sites = zap_data["site"]
            if isinstance(sites, list):
                for site in sites:
                    if "alerts" in site and isinstance(site["alerts"], list):
                        alerts.extend(site["alerts"])
            elif isinstance(sites, dict) and "alerts" in sites:
                alerts.extend(sites["alerts"])
            if alerts:
                return alerts

        if "alerts" in zap_data and isinstance(zap_data["alerts"], list):
            return zap_data["alerts"]

    return []


def calculate_impact_and_likelihood(alert_name, cwe_id, risk_code_str, confidence_str, param, evidence, attack):
    """
    Calculates numerical Impact (1-5) and Likelihood (1-5).
    Risk = Impact x Likelihood (Range: 1 - 25)
    """
    name_lower = alert_name.lower()
    cwe_str = str(cwe_id or "").strip()

    # Base Impact assessment
    if any(k in name_lower for k in ["command injection", "remote code", "rce", "sql injection"]) or cwe_str in ["78", "89"]:
        impact = 5
        impact_reason = "Critical severity: May permit arbitrary code execution, database compromise, or host control."
    elif any(k in name_lower for k in ["path traversal", "directory traversal", "deserialization", "ssrf"]) or cwe_str in ["22", "502", "918"]:
        impact = 4
        impact_reason = "High severity: Can result in unauthorized file disclosure, internal service compromise, or severe logic bypass."
    elif any(k in name_lower for k in ["cross-site scripting", "xss", "csrf", "anti-csrf", "access control", "session fixation"]) or cwe_str in ["79", "352", "384"]:
        impact = 3
        impact_reason = "Medium severity: Enables client-side execution, unauthorized actions, or session hijacking."
    elif any(k in name_lower for k in ["cookie", "csp", "content security", "clickjacking", "header", "disclosure", "information"]) or cwe_str in ["200", "693", "1004", "1021"]:
        impact = 2
        impact_reason = "Low severity: Security defense-in-depth weakness or internal reconnaissance data leak."
    else:
        # Default based on ZAP risk code if available
        risk_code = str(risk_code_str).strip()
        if risk_code == "3":
            impact = 4
            impact_reason = "Scanner identified this as a High risk vulnerability."
        elif risk_code == "2":
            impact = 3
            impact_reason = "Scanner identified this as a Medium risk vulnerability."
        else:
            impact = 2
            impact_reason = "Scanner identified this as a Low or Informational vulnerability."

    # Likelihood assessment
    conf = str(confidence_str).strip().lower()
    if conf in ["3", "high", "certain"]:
        likelihood = 4
        conf_label = "High confidence finding"
    elif conf in ["2", "medium"]:
        likelihood = 3
        conf_label = "Medium confidence finding"
    else:
        likelihood = 2
        conf_label = "Low confidence finding"

    # Likelihood modifiers
    if param:
        likelihood = min(5, likelihood + 1)
        conf_label += ", verifiable target parameter present"
    if attack or evidence:
        likelihood = min(5, likelihood + 1)
        conf_label += ", confirmed exploit payload / response evidence"

    likelihood = max(1, min(5, likelihood))
    likelihood_reason = f"Likelihood rated {likelihood}/5 ({conf_label})."

    return impact, impact_reason, likelihood, likelihood_reason


def classify_severity(risk_score):
    """Classifies risk score into Critical, High, Medium, or Low."""
    if risk_score >= 16:
        return "Critical"
    elif risk_score >= 11:
        return "High"
    elif risk_score >= 6:
        return "Medium"
    else:
        return "Low"


def process_zap_report(zap_json_content, default_target_url="https://example.com"):
    """
    Parses ZAP report, calculates prioritized risk rankings, and associates remediation.
    """
    if isinstance(zap_json_content, str):
        try:
            zap_data = json.loads(zap_json_content)
        except Exception as e:
            zap_data = {}
    else:
        zap_data = zap_json_content

    raw_alerts = parse_zap_alerts(zap_data)
    processed_findings = []

    for item in raw_alerts:
        alert_name = item.get("name") or item.get("alert") or "Security Alert"
        plugin_id = str(item.get("pluginId", ""))
        cwe_id = str(item.get("cweid", "0"))
        cwe_display = f"CWE-{cwe_id}" if cwe_id and cwe_id != "0" else "CWE-General"
        zap_risk = str(item.get("riskdesc") or item.get("riskcode") or "Medium")
        zap_confidence = str(item.get("confidence", "Medium"))
        
        # Extract instance details
        instances = item.get("instances", [])
        inst = instances[0] if isinstance(instances, list) and len(instances) > 0 else {}
        url = inst.get("uri") or default_target_url
        param = inst.get("param", "")
        attack = inst.get("attack", "")
        evidence = inst.get("evidence", "")

        description = item.get("desc", "").replace("<p>", "").replace("</p>", "").strip()
        reference = item.get("reference", "").replace("<p>", "").replace("</p>", "").strip()

        # Calculate Impact, Likelihood and Risk Score
        impact, impact_reason, likelihood, likelihood_reason = calculate_impact_and_likelihood(
            alert_name=alert_name,
            cwe_id=cwe_id,
            risk_code_str=item.get("riskcode", "2"),
            confidence_str=zap_confidence,
            param=param,
            evidence=evidence,
            attack=attack
        )

        risk_score = impact * likelihood
        severity = classify_severity(risk_score)
        owasp_category = map_owasp_category(alert_name, cwe_id)

        # Knowledge Base remediation details
        rem_kb = lookup_remediation(alert_name=alert_name, cwe_id=cwe_display, zap_risk=zap_risk)

        processed_findings.append({
            "plugin_id": plugin_id,
            "alert_name": alert_name,
            "cwe_id": cwe_display,
            "cwe_title": rem_kb.get("cwe_title", "Common Weakness Enumeration"),
            "owasp_category": owasp_category,
            "zap_risk": zap_risk,
            "zap_confidence": zap_confidence,
            "impact": impact,
            "impact_reason": impact_reason,
            "likelihood": likelihood,
            "likelihood_reason": likelihood_reason,
            "risk_score": risk_score,
            "severity": severity,
            "url": url,
            "param": param,
            "attack": attack,
            "evidence": evidence,
            "description": description or rem_kb.get("simple_explanation", ""),
            "remediation_summary": rem_kb.get("simple_explanation", ""),
            "remediation_impact": rem_kb.get("impact", ""),
            "remediation_fix": rem_kb.get("defensive_fix", ""),
            "secure_code_example": rem_kb.get("secure_code_example", ""),
            "reference": reference or "https://owasp.org/"
        })

    # Sort findings by Risk Score descending (highest risk first), then Impact descending
    processed_findings.sort(key=lambda x: (x["risk_score"], x["impact"]), reverse=True)

    # Assign priority ranks (1, 2, 3...)
    for idx, finding in enumerate(processed_findings, start=1):
        finding["priority_rank"] = idx

    # Compute summary statistics
    total = len(processed_findings)
    crit_count = sum(1 for f in processed_findings if f["severity"] == "Critical")
    high_count = sum(1 for f in processed_findings if f["severity"] == "High")
    med_count = sum(1 for f in processed_findings if f["severity"] == "Medium")
    low_count = sum(1 for f in processed_findings if f["severity"] == "Low")

    if total > 0:
        avg_risk = sum(f["risk_score"] for f in processed_findings) / total
    else:
        avg_risk = 0.0

    if crit_count > 0:
        overall_risk_level = "CRITICAL RISK"
    elif high_count > 0:
        overall_risk_level = "HIGH RISK"
    elif med_count > 0:
        overall_risk_level = "MEDIUM RISK"
    else:
        overall_risk_level = "LOW RISK"

    summary_stats = {
        "total_findings": total,
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "overall_risk_score": round(avg_risk, 1),
        "overall_risk_level": overall_risk_level,
        "chart_data": {
            "labels": ["Critical", "High", "Medium", "Low"],
            "counts": [crit_count, high_count, med_count, low_count],
            "colors": ["#dc2626", "#ea580c", "#d97706", "#16a34a"]
        }
    }

    return processed_findings, summary_stats
