"""
CloudGuard SQLite Database Layer
Handles database schema initialization, schema migrations, and persistence for scans and findings.
Always resolves absolute path relative to project root.
"""
import os
import sqlite3
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

# Always resolve to project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(BASE_DIR, "cloudguard.db")


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with dict-like row access."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def create_database():
    """
    Initializes database tables and migrates existing schema if needed.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            score INTEGER NOT NULL DEFAULT 100,
            total_findings INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'COMPLETED'
        )
    """)

    # 2. Findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            service TEXT NOT NULL,
            resource TEXT NOT NULL,
            issue TEXT NOT NULL,
            risk TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Schema migration check: ensure scan_id column exists on findings table
    cursor.execute("PRAGMA table_info(findings)")
    columns = [row["name"] for row in cursor.fetchall()]
    if "scan_id" not in columns:
        cursor.execute("ALTER TABLE findings ADD COLUMN scan_id TEXT")

    conn.commit()
    conn.close()


def record_scan(
    scan_id: str,
    start_time: str,
    end_time: str,
    score: int,
    total_findings: int,
    status: str = "COMPLETED",
) -> Dict[str, Any]:
    """Records a completed security scan entry."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans (scan_id, start_time, end_time, score, total_findings, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_id, start_time, end_time, score, total_findings, status))

    conn.commit()
    conn.close()

    return {
        "scan_id": scan_id,
        "start_time": start_time,
        "end_time": end_time,
        "score": score,
        "total_findings": total_findings,
        "status": status,
    }


def save_findings(findings: List[Dict[str, Any]], scan_id: Optional[str] = None):
    """
    Saves a batch of findings associated with an optional scan_id.
    """
    if not findings:
        return

    conn = get_db_connection()
    cursor = conn.cursor()

    for finding in findings:
        scan_time = finding.get("scan_time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO findings (scan_id, service, resource, issue, risk, recommendation, scan_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id or finding.get("scan_id"),
            finding.get("service", "UNKNOWN"),
            finding.get("resource", "UNKNOWN"),
            finding.get("issue", ""),
            finding.get("risk", "MEDIUM"),
            finding.get("recommendation", ""),
            scan_time,
        ))

    conn.commit()
    conn.close()


def get_all_findings(
    service: Optional[str] = None,
    risk: Optional[str] = None,
    scan_id: Optional[str] = None,
    search: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieves findings with optional filters.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM findings WHERE 1=1"
    params = []

    if service:
        query += " AND UPPER(service) = ?"
        params.append(service.upper().strip())

    if risk:
        query += " AND UPPER(risk) = ?"
        params.append(risk.upper().strip())

    if scan_id:
        query += " AND scan_id = ?"
        params.append(scan_id.strip())

    if search:
        query += " AND (resource LIKE ? OR issue LIKE ? OR recommendation LIKE ?)"
        pattern = f"%{search.strip()}%"
        params.extend([pattern, pattern, pattern])

    query += " ORDER BY id DESC"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def get_finding_by_id(finding_id: int) -> Optional[Dict[str, Any]]:
    """Fetches a specific finding by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns past scans ordered chronologically descending."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """Fetches scan metadata and associated findings."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    scan_row = cursor.fetchone()

    if not scan_row:
        conn.close()
        return None

    scan_dict = dict(scan_row)
    cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id DESC", (scan_id,))
    findings_rows = cursor.fetchall()
    scan_dict["findings"] = [dict(f) for f in findings_rows]
    conn.close()
    return scan_dict


def get_latest_scan() -> Optional[Dict[str, Any]]:
    """Fetches the latest recorded scan."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


# Auto-initialize database schema on import
create_database()