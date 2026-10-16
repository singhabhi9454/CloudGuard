"""
CloudGuard Main Orchestrator Scanner
Executes scans across EC2, S3, IAM, and RDS, evaluates rules, calculates scores, and persists results.
"""
import logging
import os
import sys
import uuid
from datetime import datetime
from typing import Dict, Any, List

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scanner.security_score import calculate_security_score
from scanner.ec2_scanner import scan_ec2
from scanner.s3_scanner import scan_s3
from scanner.iam_scanner import scan_iam
from scanner.rds_scanner import scan_rds
from database.database import create_database, save_findings, record_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloudguard.main")


def run_full_scan(scan_id: str = None) -> Dict[str, Any]:
    """
    Executes a comprehensive live AWS security audit.
    Orchestrates EC2, S3, IAM, and RDS checks, persists results to SQLite,
    and returns full audit metrics.
    """
    create_database()
    active_scan_id = scan_id or f"scan-{uuid.uuid4().hex[:8]}"
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    logger.info("========================================")
    logger.info(f"   CLOUDGUARD SCAN STARTED: {active_scan_id}")
    logger.info("========================================")

    all_findings: List[Dict[str, Any]] = []

    # 1. EC2 Scan
    logger.info("🔍 [1/4] Scanning EC2 & Security Groups...")
    try:
        ec2_findings = scan_ec2()
        for f in ec2_findings:
            f["scan_id"] = active_scan_id
        all_findings.extend(ec2_findings)
    except Exception as e:
        logger.error(f"EC2 scan failed: {e}")

    # 2. S3 Scan
    logger.info("🔍 [2/4] Scanning S3 Buckets...")
    try:
        s3_findings = scan_s3()
        for f in s3_findings:
            f["scan_id"] = active_scan_id
        all_findings.extend(s3_findings)
    except Exception as e:
        logger.error(f"S3 scan failed: {e}")

    # 3. IAM Scan
    logger.info("🔍 [3/4] Scanning IAM Users & Policies...")
    try:
        iam_findings = scan_iam()
        for f in iam_findings:
            f["scan_id"] = active_scan_id
        all_findings.extend(iam_findings)
    except Exception as e:
        logger.error(f"IAM scan failed: {e}")

    # 4. RDS Scan
    logger.info("🔍 [4/4] Scanning RDS Databases...")
    try:
        rds_findings = scan_rds()
        for f in rds_findings:
            f["scan_id"] = active_scan_id
        all_findings.extend(rds_findings)
    except Exception as e:
        logger.error(f"RDS scan failed: {e}")

    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Score calculation
    score_summary = calculate_security_score(all_findings)
    score_value = score_summary["score"]
    total_count = score_summary["total"]

    # Persist findings and scan metadata
    if all_findings:
        save_findings(all_findings, scan_id=active_scan_id)

    record_scan(
        scan_id=active_scan_id,
        start_time=start_time,
        end_time=end_time,
        score=score_value,
        total_findings=total_count,
        status="COMPLETED",
    )

    result = {
        "scan_id": active_scan_id,
        "score": score_value,
        "total_findings": total_count,
        "critical": score_summary["critical"],
        "high": score_summary["high"],
        "medium": score_summary["medium"],
        "low": score_summary["low"],
        "findings": all_findings,
        "status": "COMPLETED",
        "start_time": start_time,
        "end_time": end_time,
    }

    logger.info("========================================")
    logger.info(f"   CLOUDGUARD SCAN FINISHED: {active_scan_id}")
    logger.info(f"   Score: {score_value}/100 | Findings: {total_count}")
    logger.info("========================================")

    return result


if __name__ == "__main__":
    scan_result = run_full_scan()
    print("\n================================")
    print("          SCAN RESULT")
    print("================================")
    print("Scan ID:        ", scan_result["scan_id"])
    print("Total Findings: ", scan_result["total_findings"])
    print("Critical:       ", scan_result["critical"])
    print("High:           ", scan_result["high"])
    print("Medium:         ", scan_result["medium"])
    print("Low:            ", scan_result["low"])
    print("Security Score: ", scan_result["score"], "/100")
    print("================================")

    for finding in scan_result["findings"]:
        print(f"\n[{finding['risk']}] {finding['service']} - {finding['resource']}")
        print(f"  Issue: {finding['issue']}")
        print(f"  Fix:   {finding['recommendation']}")