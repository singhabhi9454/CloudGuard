"""
CloudGuard IAM Scanner
Scans IAM users, MFA configurations, access key ages, and user policy attachments.
"""
import logging
from typing import List, Dict, Any
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from rules.iam_rules import check_iam_user

logger = logging.getLogger("cloudguard.iam")


def scan_iam() -> List[Dict[str, Any]]:
    """
    Scans IAM users and their security posture (MFA, access key age, permissions).
    Returns standardized findings. Handles empty user accounts gracefully.
    """
    all_findings: List[Dict[str, Any]] = []

    try:
        iam = boto3.client("iam")
    except Exception as e:
        logger.error(f"Failed to initialize IAM client: {e}")
        return all_findings

    try:
        response = iam.list_users()
        users = response.get("Users", [])

        if not users:
            logger.info("No IAM users found in the account.")
            return all_findings

        for user in users:
            user_name = user.get("UserName")
            if not user_name:
                continue

            logger.info(f"Scanning IAM User: {user_name}")

            user_data: Dict[str, Any] = {
                "UserName": user_name,
                "UserId": user.get("UserId"),
                "Arn": user.get("Arn"),
                "PasswordLastUsed": user.get("PasswordLastUsed"),
                "HasLoginProfile": False,
                "HasMFA": False,
                "AccessKeys": [],
                "AttachedPolicies": [],
            }

            # Check if login profile exists (console login)
            try:
                iam.get_login_profile(UserName=user_name)
                user_data["HasLoginProfile"] = True
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    logger.debug(f"Error checking login profile for {user_name}: {e}")

            # Check MFA devices
            try:
                mfa_resp = iam.list_mfa_devices(UserName=user_name)
                user_data["HasMFA"] = len(mfa_resp.get("MFADevices", [])) > 0
            except ClientError as e:
                logger.debug(f"Error checking MFA for {user_name}: {e}")

            # Check Access Keys
            try:
                keys_resp = iam.list_access_keys(UserName=user_name)
                user_data["AccessKeys"] = keys_resp.get("AccessKeyMetadata", [])
            except ClientError as e:
                logger.debug(f"Error checking access keys for {user_name}: {e}")

            # Check attached policies
            try:
                policies_resp = iam.list_attached_user_policies(UserName=user_name)
                user_data["AttachedPolicies"] = policies_resp.get("AttachedPolicies", [])
            except ClientError as e:
                logger.debug(f"Error checking policies for {user_name}: {e}")

            # Run IAM rules
            findings = check_iam_user(user_data)
            all_findings.extend(findings)

    except (ClientError, BotoCoreError) as e:
        logger.error(f"AWS IAM API error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during IAM scan: {e}")

    return all_findings


def get_iam_inventory() -> List[Dict[str, Any]]:
    """
    Returns inventory summary of IAM users and credential state.
    """
    inventory: List[Dict[str, Any]] = []
    try:
        iam = boto3.client("iam")
        users = iam.list_users().get("Users", [])
        for u in users:
            u_name = u.get("UserName")
            mfa_enabled = False
            try:
                mfa = iam.list_mfa_devices(UserName=u_name).get("MFADevices", [])
                mfa_enabled = len(mfa) > 0
            except Exception:
                pass

            inventory.append({
                "username": u_name,
                "created": str(u.get("CreateDate", "")),
                "mfa_enabled": mfa_enabled,
                "password_last_used": str(u.get("PasswordLastUsed", "Never")),
            })
    except Exception as e:
        logger.warning(f"Failed to fetch IAM inventory: {e}")

    return inventory