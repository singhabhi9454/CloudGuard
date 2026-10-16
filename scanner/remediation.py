"""
CloudGuard Safe Auto-Remediation Engine
Implements controlled, human-confirmed remediation for high-risk misconfigurations.
Never modifies cloud resources without explicit user confirmation.
"""
import logging
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("cloudguard.remediation")


def preview_remediation(
    service: str,
    resource: str,
    issue: str,
    target_cidr: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generates a dry-run preview of proposed remediation changes without modifying AWS.
    Shows current configuration and proposed configuration.
    """
    service_upper = service.upper().strip()

    if service_upper == "EC2" and "SSH" in issue:
        try:
            ec2 = boto3.client("ec2")
            response = ec2.describe_security_groups(GroupIds=[resource])
            groups = response.get("SecurityGroups", [])
            if not groups:
                return {
                    "safe": False,
                    "error": f"Security group {resource} not found in current AWS region.",
                }

            sg = groups[0]
            current_rule_found = False
            for rule in sg.get("IpPermissions", []):
                from_p = rule.get("FromPort")
                to_p = rule.get("ToPort")
                if from_p == 22 or (from_p and to_p and from_p <= 22 <= to_p):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            current_rule_found = True
                            break

            if not current_rule_found:
                return {
                    "safe": True,
                    "service": "EC2",
                    "resource": resource,
                    "status": "ALREADY_RESOLVED",
                    "message": "SSH port 22 is no longer open to 0.0.0.0/0 in this security group.",
                }

            proposed_action = "RESTRICT" if target_cidr else "REVOKE"
            proposed_desc = (
                f"Replace 0.0.0.0/0 with trusted CIDR '{target_cidr}' on port 22"
                if target_cidr
                else "Revoke 0.0.0.0/0 unrestricted inbound access on port 22"
            )

            return {
                "safe": True,
                "service": "EC2",
                "resource": resource,
                "issue": issue,
                "current_rule": {
                    "protocol": "TCP",
                    "port": 22,
                    "source": "0.0.0.0/0 (Internet / Any IP)",
                    "action": "ALLOW",
                },
                "proposed_rule": {
                    "protocol": "TCP",
                    "port": 22,
                    "source": target_cidr or "(Rule Revocation - No public access)",
                    "action": "RESTRICTED",
                    "description": proposed_desc,
                },
                "warning": (
                    "This will restrict public SSH access to this security group. "
                    "Ensure you have AWS Systems Manager (SSM) or your trusted IP specified "
                    "to prevent administrative lockout."
                ),
                "requires_confirmation": True,
            }
        except ClientError as e:
            return {"safe": False, "error": f"AWS API error: {e}"}
        except Exception as e:
            return {"safe": False, "error": f"Unexpected error: {e}"}

    # Manual remediation for other services/rules
    return {
        "safe": False,
        "service": service_upper,
        "resource": resource,
        "issue": issue,
        "manual_only": True,
        "message": (
            "Automated remediation is intentionally limited to sensitive EC2 ingress rules "
            "to prevent accidental cloud service disruption. Please follow the recommended manual guide."
        ),
    }


def apply_remediation(
    service: str,
    resource: str,
    confirmed: bool,
    target_cidr: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Applies the remediation change ONLY after explicit confirmation.
    """
    if not confirmed:
        return {
            "success": False,
            "error": "Remediation aborted: Explicit user confirmation required.",
        }

    service_upper = service.upper().strip()

    if service_upper == "EC2":
        try:
            ec2 = boto3.client("ec2")

            # 1. Revoke the 0.0.0.0/0 rule for port 22
            logger.info(f"Revoking port 22 0.0.0.0/0 on {resource}")
            ec2.revoke_security_group_ingress(
                GroupId=resource,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            )

            # 2. If user supplied trusted CIDR, authorize it
            if target_cidr and target_cidr.strip():
                clean_cidr = target_cidr.strip()
                logger.info(f"Authorizing trusted CIDR {clean_cidr} on {resource}")
                ec2.authorize_security_group_ingress(
                    GroupId=resource,
                    IpPermissions=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": clean_cidr, "Description": "CloudGuard Trusted Access"}],
                        }
                    ],
                )

            return {
                "success": True,
                "service": "EC2",
                "resource": resource,
                "message": (
                    f"Successfully secured {resource}. SSH port 22 open access has been revoked."
                    + (f" Restricted to {target_cidr}." if target_cidr else "")
                ),
            }

        except ClientError as e:
            logger.error(f"Failed to apply EC2 remediation: {e}")
            return {"success": False, "error": f"AWS Error: {e.response.get('Error', {}).get('Message', str(e))}"}
        except Exception as e:
            logger.error(f"Unexpected error in remediation: {e}")
            return {"success": False, "error": str(e)}

    return {
        "success": False,
        "error": f"No automated remediation handler for {service}.",
    }
