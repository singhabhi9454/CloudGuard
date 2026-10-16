"""
CloudGuard IAM Security Rules
Evaluates IAM users, access keys, MFA, and privileges against AWS best practices.
"""
from typing import List, Dict, Any
from scanner.finding import create_finding
from rules.common_rules import days_since


def check_iam_user(user_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates an IAM user object with attached MFA and Access Key metadata.
    """
    findings: List[Dict[str, Any]] = []
    user_name = user_data.get("UserName", "unknown-user")

    # 1. Console access without MFA
    has_console = user_data.get("PasswordLastUsed") is not None or user_data.get("HasLoginProfile", False)
    has_mfa = user_data.get("HasMFA", False)

    if has_console and not has_mfa:
        findings.append(
            create_finding(
                service="IAM",
                resource=user_name,
                issue="IAM user has console access without Multi-Factor Authentication (MFA)",
                risk="HIGH",
                recommendation="Enforce MFA for all IAM users with AWS Management Console access.",
            )
        )

    # 2. Access keys older than 90 days
    access_keys = user_data.get("AccessKeys", [])
    for key in access_keys:
        if key.get("Status") == "Active":
            create_date = key.get("CreateDate")
            age = days_since(create_date)
            key_id = key.get("AccessKeyId", "")
            if age > 90:
                findings.append(
                    create_finding(
                        service="IAM",
                        resource=f"{user_name} ({key_id[-4:]})",
                        issue=f"IAM access key is {age} days old (exceeds 90-day threshold)",
                        risk="MEDIUM",
                        recommendation="Rotate IAM access keys every 90 days or migrate to IAM Identity Center / Roles.",
                    )
                )

    # 3. Excessive permissions / AdministratorAccess
    attached_policies = user_data.get("AttachedPolicies", [])
    for policy in attached_policies:
        policy_name = policy.get("PolicyName", "")
        if "AdministratorAccess" in policy_name:
            findings.append(
                create_finding(
                    service="IAM",
                    resource=user_name,
                    issue="IAM user has AdministratorAccess policy attached directly",
                    risk="HIGH",
                    recommendation="Apply principle of least privilege; assign permissions via IAM groups or temporary assume-role sessions.",
                )
            )

    return findings


def check_root_account(summary_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Checks root account security summary flags.
    """
    findings: List[Dict[str, Any]] = []

    # Root access keys active
    if summary_data.get("AccountAccessKeysPresent", 0) > 0:
        findings.append(
            create_finding(
                service="IAM",
                resource="AWS-Root-Account",
                issue="Root account has active access keys",
                risk="CRITICAL",
                recommendation="Delete all root account access keys immediately and use IAM users or roles.",
            )
        )

    # Root MFA missing
    if summary_data.get("AccountMFAEnabled", 1) == 0:
        findings.append(
            create_finding(
                service="IAM",
                resource="AWS-Root-Account",
                issue="Root account does not have MFA enabled",
                risk="CRITICAL",
                recommendation="Enable hardware or virtual MFA device on the root AWS account immediately.",
            )
        )

    return findings