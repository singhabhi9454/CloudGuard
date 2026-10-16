"""
CloudGuard RDS Scanner
Scans Amazon RDS database instances for public accessibility and storage encryption.
"""
import logging
from typing import List, Dict, Any
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from rules.rds_rules import check_rds_instance

logger = logging.getLogger("cloudguard.rds")


def scan_rds() -> List[Dict[str, Any]]:
    """
    Scans RDS DB instances in the current region for security configurations.
    Returns standardized findings. Handles empty databases or permission restrictions gracefully.
    """
    all_findings: List[Dict[str, Any]] = []

    try:
        rds = boto3.client("rds")
    except Exception as e:
        logger.error(f"Failed to initialize RDS client: {e}")
        return all_findings

    try:
        response = rds.describe_db_instances()
        db_instances = response.get("DBInstances", [])

        if not db_instances:
            logger.info("No RDS database instances found in the current region.")
            return all_findings

        for db in db_instances:
            db_identifier = db.get("DBInstanceIdentifier", "unknown-db")
            engine = db.get("Engine", "unknown")
            logger.info(f"Scanning RDS Instance: {db_identifier} (Engine: {engine})")

            findings = check_rds_instance(db)
            all_findings.extend(findings)

    except (ClientError, BotoCoreError) as e:
        logger.error(f"AWS RDS API error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during RDS scan: {e}")

    return all_findings


def get_rds_inventory() -> List[Dict[str, Any]]:
    """
    Returns inventory summary of RDS instances.
    """
    inventory: List[Dict[str, Any]] = []
    try:
        rds = boto3.client("rds")
        db_instances = rds.describe_db_instances().get("DBInstances", [])
        for db in db_instances:
            inventory.append({
                "identifier": db.get("DBInstanceIdentifier"),
                "engine": db.get("Engine"),
                "status": db.get("DBInstanceStatus"),
                "publicly_accessible": db.get("PubliclyAccessible", False),
                "encrypted": db.get("StorageEncrypted", False),
                "allocated_storage": db.get("AllocatedStorage"),
            })
    except Exception as e:
        logger.warning(f"Failed to fetch RDS inventory: {e}")

    return inventory