"""
CloudGuard Finding Model and Constructor
Standardized finding structure across all AWS scanners.
"""
from datetime import datetime
from typing import Optional, Dict, Any

VALID_RISKS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def create_finding(
    service: str,
    resource: str,
    issue: str,
    risk: str,
    recommendation: str,
    scan_time: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Creates a standardized CloudGuard security finding.

    Format:
    {
        "service": "EC2" | "S3" | "IAM" | "RDS",
        "resource": "sg-xxxx" | "bucket-name" | "user-name" | "db-instance",
        "issue": "Description of misconfiguration",
        "risk": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
        "recommendation": "Remediation guidance",
        "scan_time": "YYYY-MM-DD HH:MM:SS"
    }
    """
    normalized_risk = risk.upper().strip() if risk else "MEDIUM"
    if normalized_risk not in VALID_RISKS:
        normalized_risk = "MEDIUM"

    normalized_service = service.upper().strip() if service else "UNKNOWN"
    formatted_time = scan_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return {
        "service": normalized_service,
        "resource": str(resource).strip(),
        "issue": str(issue).strip(),
        "risk": normalized_risk,
        "recommendation": str(recommendation).strip(),
        "scan_time": formatted_time,
    }