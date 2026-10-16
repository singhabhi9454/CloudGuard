"""
CloudGuard S3 Scanner
Scans Amazon S3 buckets for Public Access Block, encryption, and open policies.
"""
import logging
from typing import List, Dict, Any
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from rules.s3_rules import check_s3_bucket

logger = logging.getLogger("cloudguard.s3")


def scan_s3() -> List[Dict[str, Any]]:
    """
    Scans all accessible S3 buckets in the AWS account.
    Returns standardized findings. Handles permission errors gracefully.
    """
    all_findings: List[Dict[str, Any]] = []

    try:
        s3 = boto3.client("s3")
    except Exception as e:
        logger.error(f"Failed to initialize S3 client: {e}")
        return all_findings

    try:
        response = s3.list_buckets()
        buckets = response.get("Buckets", [])

        if not buckets:
            logger.info("No S3 buckets found in the AWS account.")
            return all_findings

        for bucket in buckets:
            bucket_name = bucket.get("Name")
            if not bucket_name:
                continue

            logger.info(f"Scanning S3 Bucket: {bucket_name}")

            bucket_data: Dict[str, Any] = {
                "Name": bucket_name,
                "CreationDate": str(bucket.get("CreationDate", "")),
            }

            # 1. Public Access Block
            try:
                pab_resp = s3.get_public_access_block(Bucket=bucket_name)
                bucket_data["PublicAccessBlock"] = pab_resp.get("PublicAccessBlockConfiguration", {})
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code")
                if error_code == "NoSuchPublicAccessBlockConfiguration":
                    bucket_data["PublicAccessBlock"] = {}
                else:
                    logger.warning(f"Could not read Public Access Block for {bucket_name}: {error_code}")
                    bucket_data["PublicAccessBlock"] = {}
            except Exception:
                bucket_data["PublicAccessBlock"] = {}

            # 2. Server-Side Encryption
            try:
                enc_resp = s3.get_bucket_encryption(Bucket=bucket_name)
                bucket_data["Encryption"] = enc_resp.get("ServerSideEncryptionConfiguration", {})
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code")
                if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                    bucket_data["Encryption"] = {}
                else:
                    bucket_data["Encryption"] = {}
            except Exception:
                bucket_data["Encryption"] = {}

            # 3. Policy Status (Public check)
            try:
                policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
                bucket_data["PolicyStatus"] = policy_status.get("PolicyStatus", {})
            except ClientError:
                bucket_data["PolicyStatus"] = {"IsPublic": False}
            except Exception:
                bucket_data["PolicyStatus"] = {"IsPublic": False}

            # 4. Versioning
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                bucket_data["Versioning"] = {"Status": versioning.get("Status", "Disabled")}
            except Exception:
                bucket_data["Versioning"] = {"Status": "Disabled"}

            # Run S3 rules engine
            findings = check_s3_bucket(bucket_data)
            all_findings.extend(findings)

    except (ClientError, BotoCoreError) as e:
        logger.error(f"AWS S3 API error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during S3 scan: {e}")

    return all_findings


def get_s3_inventory() -> List[Dict[str, Any]]:
    """
    Returns list of discovered S3 buckets with status summaries.
    """
    inventory: List[Dict[str, Any]] = []
    try:
        s3 = boto3.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            b_name = b.get("Name")
            pab_active = False
            try:
                pab = s3.get_public_access_block(Bucket=b_name).get("PublicAccessBlockConfiguration", {})
                pab_active = pab.get("BlockPublicAcls", False) and pab.get("BlockPublicPolicy", False)
            except Exception:
                pass

            inventory.append({
                "name": b_name,
                "created": str(b.get("CreationDate", "")),
                "public_block_active": pab_active,
            })
    except Exception as e:
        logger.warning(f"Failed to fetch S3 inventory: {e}")

    return inventory