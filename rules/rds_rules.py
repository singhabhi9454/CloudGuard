"""
CloudGuard RDS Security Rules
Evaluates RDS instances for public exposure, storage encryption, and backup configurations.
"""
from typing import List, Dict, Any
from scanner.finding import create_finding


def check_rds_instance(db_instance: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Checks an RDS database instance for misconfigurations.
    """
    findings: List[Dict[str, Any]] = []

    db_identifier = db_instance.get("DBInstanceIdentifier", "unknown-db")
    publicly_accessible = db_instance.get("PubliclyAccessible", False)
    storage_encrypted = db_instance.get("StorageEncrypted", True)
    backup_retention = db_instance.get("BackupRetentionPeriod", 1)
    auto_minor_version_upgrade = db_instance.get("AutoMinorVersionUpgrade", True)
    multi_az = db_instance.get("MultiAZ", False)

    # 1. Public accessibility (Preserve core message)
    if publicly_accessible:
        findings.append(
            create_finding(
                service="RDS",
                resource=db_identifier,
                issue="RDS database is publicly accessible",
                risk="HIGH",
                recommendation="Disable public accessibility and keep the database in a private subnet",
            )
        )

    # 2. Storage encryption
    if not storage_encrypted:
        findings.append(
            create_finding(
                service="RDS",
                resource=db_identifier,
                issue="RDS database storage is not encrypted at rest",
                risk="HIGH",
                recommendation="Enable AWS KMS encryption at rest for RDS database instances and snapshots.",
            )
        )

    # 3. Automated backups disabled
    if backup_retention == 0:
        findings.append(
            create_finding(
                service="RDS",
                resource=db_identifier,
                issue="RDS automated backups are disabled (Retention = 0 days)",
                risk="MEDIUM",
                recommendation="Set automated backup retention period to at least 7 days for disaster recovery.",
            )
        )

    # 4. Auto minor version upgrade disabled
    if not auto_minor_version_upgrade:
        findings.append(
            create_finding(
                service="RDS",
                resource=db_identifier,
                issue="RDS automatic minor version upgrade is disabled",
                risk="LOW",
                recommendation="Enable auto minor version upgrades to receive security patches automatically.",
            )
        )

    # 5. Multi-AZ disabled (for high availability)
    if not multi_az:
        findings.append(
            create_finding(
                service="RDS",
                resource=db_identifier,
                issue="RDS Multi-AZ high availability deployment is disabled",
                risk="LOW",
                recommendation="Enable Multi-AZ deployment for production RDS databases to ensure failover resilience.",
            )
        )

    return findings