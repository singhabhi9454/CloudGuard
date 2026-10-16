"""
CloudGuard S3 Security Rules
Evaluates S3 Bucket configurations for public exposure, encryption, and policy risks.
"""
from typing import List, Dict, Any
from scanner.finding import create_finding


def check_s3_bucket(bucket: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Checks an S3 bucket for missing Public Access Block, open policies, and missing encryption.
    """
    findings: List[Dict[str, Any]] = []
    bucket_name = bucket.get("Name", "unknown-bucket")

    # 1. Check Public Access Block
    public_access = bucket.get("PublicAccessBlock", {})
    if not public_access:
        findings.append(
            create_finding(
                service="S3",
                resource=bucket_name,
                issue="S3 bucket does not have Public Access Block configured",
                risk="HIGH",
                recommendation="Enable S3 Block Public Access to protect bucket from public visibility.",
            )
        )
    else:
        # Check if public access block flags are properly enforced
        all_blocked = (
            public_access.get("BlockPublicAcls", False)
            and public_access.get("IgnorePublicAcls", False)
            and public_access.get("BlockPublicPolicy", False)
            and public_access.get("RestrictPublicBuckets", False)
        )
        if not all_blocked:
            findings.append(
                create_finding(
                    service="S3",
                    resource=bucket_name,
                    issue="S3 Public Access Block has partial protections disabled",
                    risk="MEDIUM",
                    recommendation="Enable all four S3 Block Public Access settings (Acls & Policies).",
                )
            )

    # 2. Check Server-Side Encryption
    encryption = bucket.get("Encryption", {})
    has_encryption = False
    if isinstance(encryption, dict):
        if encryption.get("Rules") or encryption.get("ServerSideEncryptionConfiguration") or encryption.get("ApplyServerSideEncryptionByDefault"):
            has_encryption = True

    if not has_encryption:
        findings.append(
            create_finding(
                service="S3",
                resource=bucket_name,
                issue="S3 bucket default server-side encryption is disabled",
                risk="MEDIUM",
                recommendation="Enable default server-side encryption using AWS KMS or AES-256 (SSE-S3).",
            )
        )

    # 3. Check Public Bucket Policy
    policy_status = bucket.get("PolicyStatus", {})
    if policy_status.get("IsPublic", False):
        findings.append(
            create_finding(
                service="S3",
                resource=bucket_name,
                issue="S3 bucket policy allows public access",
                risk="CRITICAL",
                recommendation="Remove wildcard public permissions from the bucket policy.",
            )
        )

    return findings