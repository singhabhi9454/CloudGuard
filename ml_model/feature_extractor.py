"""
CloudGuard Feature Extractor
Extracts and normalizes machine learning features from live AWS scanner findings,
resource inventories, or structured configuration dictionaries.
"""
from typing import Dict, Any, List, Optional
import pandas as pd

FEATURE_NAMES = [
    "ssh_port_22_open",
    "rdp_port_3389_open",
    "all_traffic_open",
    "sensitive_ports_open",
    "s3_public_access_block_disabled",
    "s3_bucket_policy_public",
    "s3_encryption_disabled",
    "iam_console_without_mfa",
    "iam_access_key_age_over_90d",
    "iam_admin_policy_attached",
    "rds_publicly_accessible",
    "rds_encryption_disabled",
    "rds_backup_disabled",
]

FEATURE_DESCRIPTIONS = {
    "ssh_port_22_open": "EC2 Ingress: SSH Port 22 open to 0.0.0.0/0",
    "rdp_port_3389_open": "EC2 Ingress: RDP Port 3389 open to 0.0.0.0/0",
    "all_traffic_open": "EC2 Ingress: All traffic (all ports) unrestricted",
    "sensitive_ports_open": "EC2 Ingress: Database/Management ports exposed to internet",
    "s3_public_access_block_disabled": "S3 Storage: Block Public Access missing or disabled",
    "s3_bucket_policy_public": "S3 Storage: Bucket policy grants public wildcard access",
    "s3_encryption_disabled": "S3 Storage: Server-side default encryption disabled",
    "iam_console_without_mfa": "IAM Identity: Console login profile active without MFA",
    "iam_access_key_age_over_90d": "IAM Identity: Active access key unrotated for > 90 days",
    "iam_admin_policy_attached": "IAM Identity: AdministratorAccess directly attached",
    "rds_publicly_accessible": "RDS Database: Publicly accessible database instance",
    "rds_encryption_disabled": "RDS Database: Storage encryption disabled at rest",
    "rds_backup_disabled": "RDS Database: Automated backup retention disabled (0 days)",
}


def get_feature_names() -> List[str]:
    """Returns the ordered list of model features."""
    return list(FEATURE_NAMES)


def extract_features_from_dict(config: Dict[str, Any]) -> Dict[str, int]:
    """
    Extracts and normalizes features from a dictionary or API payload.
    Supports boolean values, integer flags (0/1), and common aliases.
    Does not assume missing values mean the environment is secure.
    """
    if not isinstance(config, dict):
        raise ValueError(f"Expected dictionary input for feature extraction, received {type(config).__name__}")

    extracted = {}

    alias_map = {
        "ssh_port_22_open": ["ssh_port_22_open", "ssh_open", "open_ssh", "ssh_port_22"],
        "rdp_port_3389_open": ["rdp_port_3389_open", "rdp_open", "open_rdp", "rdp_port_3389"],
        "all_traffic_open": ["all_traffic_open", "unrestricted_traffic", "open_all_traffic"],
        "sensitive_ports_open": ["sensitive_ports_open", "db_ports_open", "database_ports_open"],
        "s3_public_access_block_disabled": [
            "s3_public_access_block_disabled",
            "s3_pab_disabled",
            "s3_public_access",
            "s3_no_public_block",
        ],
        "s3_bucket_policy_public": ["s3_bucket_policy_public", "s3_public_policy", "public_bucket_policy"],
        "s3_encryption_disabled": [
            "s3_encryption_disabled",
            "s3_no_encryption",
            "s3_unencrypted",
        ],
        "iam_console_without_mfa": [
            "iam_console_without_mfa",
            "iam_no_mfa",
            "console_no_mfa",
            "mfa_disabled",
        ],
        "iam_access_key_age_over_90d": [
            "iam_access_key_age_over_90d",
            "iam_old_access_key",
            "old_access_keys",
            "access_key_stale",
        ],
        "iam_admin_policy_attached": [
            "iam_admin_policy_attached",
            "iam_admin_direct",
            "admin_access_attached",
        ],
        "rds_publicly_accessible": [
            "rds_publicly_accessible",
            "rds_public",
            "public_rds",
        ],
        "rds_encryption_disabled": [
            "rds_encryption_disabled",
            "rds_no_encryption",
            "rds_unencrypted",
        ],
        "rds_backup_disabled": [
            "rds_backup_disabled",
            "rds_no_backup",
            "backup_retention_zero",
        ],
    }

    for standard_feature, aliases in alias_map.items():
        val = None
        for alias in aliases:
            if alias in config:
                val = config[alias]
                break

        if val is None:
            # Default to 0 if not specified in input
            extracted[standard_feature] = 0
        elif isinstance(val, bool):
            extracted[standard_feature] = 1 if val else 0
        elif isinstance(val, (int, float)):
            extracted[standard_feature] = 1 if val > 0 else 0
        elif isinstance(val, str):
            clean_str = val.strip().lower()
            if clean_str in ("1", "true", "yes", "enabled", "open", "high", "critical"):
                extracted[standard_feature] = 1
            else:
                extracted[standard_feature] = 0
        else:
            extracted[standard_feature] = 0

    return extracted


def extract_features_from_findings(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Converts live CloudGuard security findings into model input features.
    Maps real AWS scanner discoveries directly to feature flags.
    """
    features = {f_name: 0 for f_name in FEATURE_NAMES}

    if not findings:
        return features

    for finding in findings:
        service = str(finding.get("service", "")).upper()
        issue = str(finding.get("issue", "")).lower()

        # EC2 checks
        if service == "EC2":
            if "ssh" in issue or "port 22" in issue:
                features["ssh_port_22_open"] = 1
            if "rdp" in issue or "port 3389" in issue:
                features["rdp_port_3389_open"] = 1
            if "all traffic" in issue or "all ports" in issue:
                features["all_traffic_open"] = 1
            if any(term in issue for term in ["mysql", "postgresql", "redis", "mongodb", "telnet", "port 3306", "port 5432"]):
                features["sensitive_ports_open"] = 1

        # S3 checks
        elif service == "S3":
            if "public access block" in issue:
                features["s3_public_access_block_disabled"] = 1
            if "policy allows public" in issue or "public access" in issue:
                features["s3_bucket_policy_public"] = 1
            if "encryption is disabled" in issue or "unencrypted" in issue:
                features["s3_encryption_disabled"] = 1

        # IAM checks
        elif service == "IAM":
            if "mfa" in issue or "without multi-factor" in issue:
                features["iam_console_without_mfa"] = 1
            if "90-day threshold" in issue or "old" in issue or "access key" in issue:
                features["iam_access_key_age_over_90d"] = 1
            if "administratoraccess" in issue or "excessive" in issue:
                features["iam_admin_policy_attached"] = 1

        # RDS checks
        elif service == "RDS":
            if "publicly accessible" in issue:
                features["rds_publicly_accessible"] = 1
            if "not encrypted" in issue or "encryption" in issue:
                features["rds_encryption_disabled"] = 1
            if "backups are disabled" in issue or "retention" in issue:
                features["rds_backup_disabled"] = 1

    return features


def features_to_dataframe(features: Dict[str, int]) -> pd.DataFrame:
    """
    Converts a feature dictionary into a single-row pandas DataFrame
    matching the exact feature order expected by scikit-learn.
    """
    row = [features.get(f, 0) for f in FEATURE_NAMES]
    return pd.DataFrame([row], columns=FEATURE_NAMES)
