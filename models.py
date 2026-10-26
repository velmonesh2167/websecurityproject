"""
Database models and SQLite helper functions for SecureScan.
"""

import sqlite3
import os
import datetime
import uuid

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_scan.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_uuid TEXT UNIQUE,
        target_url TEXT NOT NULL,
        consent INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'queued',
        progress INTEGER NOT NULL DEFAULT 0,
        current_step TEXT DEFAULT 'Initializing...',
        created_at TEXT NOT NULL,
        total_findings INTEGER DEFAULT 0,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        overall_risk_score REAL DEFAULT 0.0,
        overall_risk_level TEXT DEFAULT 'LOW RISK'
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        plugin_id TEXT,
        alert_name TEXT NOT NULL,
        cwe_id TEXT,
        cwe_title TEXT,
        owasp_category TEXT,
        zap_risk TEXT,
        zap_confidence TEXT,
        impact INTEGER NOT NULL,
        impact_reason TEXT,
        likelihood INTEGER NOT NULL,
        likelihood_reason TEXT,
        risk_score INTEGER NOT NULL,
        severity TEXT NOT NULL,
        priority_rank INTEGER NOT NULL,
        url TEXT,
        param TEXT,
        attack TEXT,
        evidence TEXT,
        description TEXT,
        remediation_summary TEXT,
        remediation_impact TEXT,
        remediation_fix TEXT,
        secure_code_example TEXT,
        reference TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    );
    """)

    conn.commit()
    conn.close()


def create_scan(target_url, consent=1):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_uuid = f"scan_{int(datetime.datetime.now().timestamp() * 1000)}_{uuid.uuid4().hex[:6]}"
    
    cursor.execute("""
        INSERT INTO scans (scan_uuid, target_url, consent, status, progress, current_step, created_at)
        VALUES (?, ?, ?, 'connecting', 15, 'Connecting to authorized target...', ?)
    """, (scan_uuid, target_url, consent, now_str))
    
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def update_scan_progress(scan_id, progress, step, status="in_progress"):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE scans
        SET progress = ?, current_step = ?, status = ?
        WHERE id = ?
    """, (progress, step, status, scan_id))
    conn.commit()
    conn.close()


def complete_scan(scan_id, summary_stats):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE scans
        SET status = 'completed',
            progress = 100,
            current_step = 'Assessment complete. Report generated.',
            total_findings = ?,
            critical_count = ?,
            high_count = ?,
            medium_count = ?,
            low_count = ?,
            overall_risk_score = ?,
            overall_risk_level = ?
        WHERE id = ?
    """, (
        summary_stats.get("total_findings", 0),
        summary_stats.get("critical_count", 0),
        summary_stats.get("high_count", 0),
        summary_stats.get("medium_count", 0),
        summary_stats.get("low_count", 0),
        summary_stats.get("overall_risk_score", 0.0),
        summary_stats.get("overall_risk_level", "LOW RISK"),
        scan_id
    ))
    conn.commit()
    conn.close()


def save_findings(scan_id, findings_list):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    for item in findings_list:
        cursor.execute("""
            INSERT INTO findings (
                scan_id, plugin_id, alert_name, cwe_id, cwe_title,
                owasp_category, zap_risk, zap_confidence, impact, impact_reason,
                likelihood, likelihood_reason, risk_score, severity, priority_rank,
                url, param, attack, evidence, description,
                remediation_summary, remediation_impact, remediation_fix,
                secure_code_example, reference
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            item.get("plugin_id", ""),
            item.get("alert_name", ""),
            item.get("cwe_id", ""),
            item.get("cwe_title", ""),
            item.get("owasp_category", ""),
            item.get("zap_risk", ""),
            item.get("zap_confidence", ""),
            item.get("impact", 1),
            item.get("impact_reason", ""),
            item.get("likelihood", 1),
            item.get("likelihood_reason", ""),
            item.get("risk_score", 1),
            item.get("severity", "Low"),
            item.get("priority_rank", 1),
            item.get("url", ""),
            item.get("param", ""),
            item.get("attack", ""),
            item.get("evidence", ""),
            item.get("description", ""),
            item.get("remediation_summary", ""),
            item.get("remediation_impact", ""),
            item.get("remediation_fix", ""),
            item.get("secure_code_example", ""),
            item.get("reference", "")
        ))
    
    conn.commit()
    conn.close()


def get_scan(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_latest_scan():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_scan_findings(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM findings
        WHERE scan_id = ?
        ORDER BY priority_rank ASC
    """, (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
