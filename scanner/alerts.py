"""
CloudGuard Alerts Engine
Evaluates findings for critical/high threshold breaches and sends optional notifications.
Credentials are read strictly from environment variables.
"""
import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any

logger = logging.getLogger("cloudguard.alerts")


def get_active_alerts(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identifies high and critical risk findings that require immediate attention.
    """
    alerts = []
    for f in findings:
        risk = (f.get("risk") or "").upper().strip()
        if risk in ("CRITICAL", "HIGH"):
            alerts.append({
                "severity": risk,
                "title": f"Security Alert: {f.get('service')} - {f.get('resource')}",
                "message": f.get("issue"),
                "recommendation": f.get("recommendation"),
                "resource": f.get("resource"),
                "service": f.get("service"),
                "timestamp": f.get("scan_time"),
            })
    return alerts


def dispatch_email_alert(scan_summary: Dict[str, Any]) -> bool:
    """
    Dispatches email alert via SMTP if credentials are provided in environment variables.
    Fails safely without raising if unconfigured.
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    recipient = os.getenv("ALERT_RECIPIENT_EMAIL")

    if not all([smtp_host, smtp_user, smtp_pass, recipient]):
        logger.debug("SMTP environment variables not configured. Skipping external email dispatch.")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_user
        msg["To"] = recipient
        msg["Subject"] = f"[CloudGuard Alert] AWS Security Findings Detected (Score: {scan_summary.get('score')}/100)"

        body = (
            f"CloudGuard Security Scan Alert\n\n"
            f"Scan ID: {scan_summary.get('scan_id')}\n"
            f"Score: {scan_summary.get('score')}/100\n"
            f"Total Findings: {scan_summary.get('total_findings')}\n"
            f"Critical: {scan_summary.get('critical')}, High: {scan_summary.get('high')}\n\n"
            f"Please check your CloudGuard dashboard immediately to review and remediate."
        )
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        logger.info(f"Dispatched email alert to {recipient}")
        return True
    except Exception as e:
        logger.warning(f"Failed to send email alert: {e}")
        return False
