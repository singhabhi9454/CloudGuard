"""
CloudGuard FastAPI REST Backend
Exposes security audit endpoints, scan orchestrator, remediation engine, and reporting services.
"""
import os
import sys
import logging
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from database.database import (
    create_database,
    get_all_findings,
    get_finding_by_id,
    get_all_scans,
    get_scan_by_id,
    get_latest_scan,
)
from scanner.main_scanner import run_full_scan
from scanner.security_score import calculate_security_score
from scanner.ec2_scanner import get_ec2_inventory
from scanner.s3_scanner import get_s3_inventory
from scanner.iam_scanner import get_iam_inventory
from scanner.rds_scanner import get_rds_inventory
from scanner.remediation import preview_remediation, apply_remediation
from reports.pdf_generator import generate_security_pdf
from scanner.scheduler import scheduler
from scanner.alerts import get_active_alerts, dispatch_email_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cloudguard.api")

app = FastAPI(
    title="CloudGuard API",
    description="AWS Cloud Security Assessment & Misconfiguration Scanner REST API",
    version="2.0.0",
)

# CORS configuration for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
create_database()


# -------------------------------------------------------------
# Pydantic Request Models
# -------------------------------------------------------------
class RemediatePreviewRequest(BaseModel):
    service: str = Field(..., example="EC2")
    resource: str = Field(..., example="sg-03f83b8b0d2a5c648")
    issue: str = Field(..., example="SSH port 22 is open to everyone")
    target_cidr: Optional[str] = Field(None, example="203.0.113.50/32")


class RemediateApplyRequest(BaseModel):
    service: str = Field(..., example="EC2")
    resource: str = Field(..., example="sg-03f83b8b0d2a5c648")
    confirmed: bool = Field(..., example=True)
    target_cidr: Optional[str] = Field(None, example="203.0.113.50/32")


class ScheduleRequest(BaseModel):
    mode: str = Field(..., example="DAILY")
    enabled: bool = Field(default=True)


# -------------------------------------------------------------
# REST Endpoints
# -------------------------------------------------------------
@app.get("/")
def home():
    """Root health and service information."""
    return {
        "service": "CloudGuard API",
        "status": "online",
        "version": "2.0.0",
        "docs": "/docs",
    }


@app.get("/health")
def health_check():
    """
    Checks AWS credentials connectivity, region, and local database status.
    """
    aws_connected = False
    aws_account_id = "N/A"
    aws_region = "N/A"
    aws_arn = "N/A"
    error_msg = None

    try:
        session = boto3.session.Session()
        aws_region = session.region_name or "us-east-1"
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        aws_connected = True
        aws_account_id = identity.get("Account", "N/A")
        aws_arn = identity.get("Arn", "N/A")
    except (NoCredentialsError, ClientError) as e:
        error_msg = str(e)
    except Exception as e:
        error_msg = str(e)

    scans = get_all_scans(limit=1)
    findings = get_all_findings()

    return {
        "status": "healthy" if aws_connected else "degraded",
        "aws_connected": aws_connected,
        "aws_region": aws_region,
        "aws_account_id": aws_account_id,
        "aws_arn": aws_arn,
        "error": error_msg,
        "total_scans_recorded": len(get_all_scans(limit=1000)),
        "active_findings_count": len(findings),
    }


@app.post("/scan")
def trigger_security_scan():
    """
    Executes a real-time comprehensive security scan across EC2, S3, IAM, and RDS.
    Calculates security score, records scan history, and returns full results.
    """
    try:
        result = run_full_scan()
        # Evaluate for email alerts if configured
        dispatch_email_alert(result)
        return result
    except Exception as e:
        logger.error(f"Scan execution error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security scan failed: {str(e)}",
        )


@app.get("/findings")
def list_findings(
    service: Optional[str] = None,
    risk: Optional[str] = None,
    scan_id: Optional[str] = None,
    search: Optional[str] = None,
):
    """
    Lists security findings with optional filtering.
    """
    findings = get_all_findings(
        service=service,
        risk=risk,
        scan_id=scan_id,
        search=search,
    )
    return findings


@app.get("/findings/{finding_id}")
def get_finding(finding_id: int):
    """Retrieves a single finding by ID."""
    finding = get_finding_by_id(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding with ID {finding_id} not found")
    return finding


@app.get("/scans")
def list_scans(limit: int = 50):
    """Retrieves historical audit scans."""
    return get_all_scans(limit=limit)


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    """Retrieves a specific scan and all findings associated with it."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID '{scan_id}' not found")
    return scan


@app.get("/score")
def get_security_score():
    """
    Calculates the current security posture score and risk breakdown.
    Based on the latest scan if available, or current database findings.
    """
    latest = get_latest_scan()
    if latest:
        # Get findings for the latest scan
        scan_id = latest["scan_id"]
        findings = get_all_findings(scan_id=scan_id)
        if findings:
            return calculate_security_score(findings)

    # Fallback to all findings in database
    findings = get_all_findings()
    return calculate_security_score(findings)


@app.get("/resources")
def get_cloud_resources():
    """
    Discovers live AWS resources inventory across EC2, S3, IAM, and RDS.
    """
    return {
        "ec2": get_ec2_inventory(),
        "s3": get_s3_inventory(),
        "iam": get_iam_inventory(),
        "rds": get_rds_inventory(),
    }


@app.post("/remediate/preview")
def remediate_preview_endpoint(payload: RemediatePreviewRequest):
    """
    Generates a safe dry-run preview of proposed remediation changes.
    Does not modify any AWS resources.
    """
    preview = preview_remediation(
        service=payload.service,
        resource=payload.resource,
        issue=payload.issue,
        target_cidr=payload.target_cidr,
    )
    return preview


@app.post("/remediate/apply")
def remediate_apply_endpoint(payload: RemediateApplyRequest):
    """
    Applies the remediation change ONLY after explicit human confirmation.
    """
    if not payload.confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Remediation cannot proceed without explicit confirmation.",
        )

    result = apply_remediation(
        service=payload.service,
        resource=payload.resource,
        confirmed=payload.confirmed,
        target_cidr=payload.target_cidr,
    )

    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result.get("error", "Remediation failed."),
        )

    return result


@app.api_route("/reports/pdf", methods=["GET", "HEAD"])
def download_pdf_report(scan_id: Optional[str] = None):
    """
    Generates and downloads a standardized CloudGuard PDF security assessment report.
    """
    # Select target scan or latest
    target_scan = None
    if scan_id:
        target_scan = get_scan_by_id(scan_id)
    else:
        latest = get_latest_scan()
        if latest:
            target_scan = get_scan_by_id(latest["scan_id"])

    findings = []
    score = 100
    active_scan_id = "manual-report"

    if target_scan:
        active_scan_id = target_scan.get("scan_id", active_scan_id)
        findings = target_scan.get("findings", [])
        score = target_scan.get("score", 100)
    else:
        findings = get_all_findings()
        score_data = calculate_security_score(findings)
        score = score_data["score"]

    score_calc = calculate_security_score(findings)
    risk_summary = {
        "critical": score_calc["critical"],
        "high": score_calc["high"],
        "medium": score_calc["medium"],
        "low": score_calc["low"],
    }

    # Fetch AWS account details
    account_id = "N/A"
    region = "ap-south-1"
    try:
        session = boto3.session.Session()
        region = session.region_name or "ap-south-1"
        account_id = session.client("sts").get_caller_identity().get("Account", "N/A")
    except Exception:
        pass

    pdf_path = generate_security_pdf(
        scan_id=active_scan_id,
        score=score,
        total_findings=len(findings),
        risk_summary=risk_summary,
        findings=findings,
        account_id=account_id,
        region=region,
    )

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"CloudGuard_Security_Report_{active_scan_id}.pdf",
    )


@app.get("/alerts")
def get_alerts():
    """Lists current high and critical alerts."""
    findings = get_all_findings()
    return get_active_alerts(findings)


@app.get("/schedule")
def get_scan_schedule():
    """Gets current scan schedule settings."""
    return scheduler.get_status()


@app.post("/schedule")
def update_scan_schedule(req: ScheduleRequest):
    """Updates scan schedule (DAILY, WEEKLY, MANUAL)."""
    return scheduler.set_schedule(mode=req.mode, enabled=req.enabled)


# -------------------------------------------------------------
# Machine Learning Risk Prediction Endpoints
# -------------------------------------------------------------
@app.post("/predict-risk")
def predict_risk_endpoint(payload: Dict[str, Any]):
    """
    Predicts AWS configuration risk category (LOW, MEDIUM, HIGH)
    using the trained Random Forest machine learning model.
    """
    try:
        from ml_model.predictor import predict_risk
        result = predict_risk(payload)
        return result
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Prediction failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Risk prediction failed: {str(e)}",
        )


@app.post("/predict-scan-risk")
def predict_scan_risk_endpoint(scan_id: Optional[str] = None):
    """
    Runs ML risk prediction on findings from a specific scan run or the latest audit.
    Enables direct comparison between deterministic rule-based evaluation and ML inference.
    """
    try:
        latest = get_latest_scan()
        findings = []
        target_scan_id = scan_id or (latest["scan_id"] if latest else "current")

        if scan_id:
            scan = get_scan_by_id(scan_id)
            if scan:
                findings = scan.get("findings", [])
        elif latest:
            findings = get_all_findings(scan_id=latest["scan_id"])
        else:
            findings = get_all_findings()

        from ml_model.predictor import predict_risk
        from scanner.security_score import calculate_security_score

        ml_result = predict_risk(findings)
        rule_score = calculate_security_score(findings)

        return {
            "ml_prediction": ml_result,
            "rule_based_evaluation": rule_score,
            "findings_count": len(findings),
            "scan_id": target_scan_id,
        }
    except Exception as e:
        logger.error(f"Scan risk prediction failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan risk prediction failed: {str(e)}",
        )


@app.get("/ml-model/info")
def get_ml_model_info():
    """Returns metadata, model version, and evaluation metrics for the active ML model."""
    try:
        from ml_model.predictor import get_model_info
        return get_model_info()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Could not load ML model info: {str(e)}",
        )