"""
CloudGuard EC2 Scanner
Scans EC2 instances and Security Groups for open ports and network exposure.
"""
import logging
from typing import List, Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from rules.ec2_rules import check_security_group_rules

logger = logging.getLogger("cloudguard.ec2")


def scan_ec2() -> List[Dict[str, Any]]:
    """
    Scans EC2 instances and associated Security Groups for security risks.
    Returns a list of standardized CloudGuard findings.
    Gracefully handles missing instances or AWS API permissions errors.
    """
    all_findings: List[Dict[str, Any]] = []

    try:
        ec2 = boto3.client("ec2")
    except Exception as e:
        logger.error(f"Failed to initialize EC2 client: {e}")
        return all_findings

    try:
        response = ec2.describe_instances()
        reservations = response.get("Reservations", [])

        scanned_instance_count = 0
        inspected_sg_ids = set()

        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                scanned_instance_count += 1
                instance_id = instance.get("InstanceId", "unknown")
                state_name = instance.get("State", {}).get("Name", "unknown")

                logger.info(f"Instance ID: {instance_id} (State: {state_name})")

                for group in instance.get("SecurityGroups", []):
                    group_id = group.get("GroupId")
                    if not group_id or group_id in inspected_sg_ids:
                        continue
                    inspected_sg_ids.add(group_id)

                    logger.info(f"Scanning Security Group: {group_id}")

                    try:
                        sg_response = ec2.describe_security_groups(GroupIds=[group_id])
                        for sg in sg_response.get("SecurityGroups", []):
                            findings = check_security_group_rules(
                                sg.get("IpPermissions", []),
                                group_id,
                            )
                            all_findings.extend(findings)
                    except (ClientError, BotoCoreError) as sg_err:
                        logger.warning(f"Error describing security group {group_id}: {sg_err}")

        if scanned_instance_count == 0:
            logger.info("No active EC2 instances found in the current region.")

    except (ClientError, BotoCoreError) as e:
        logger.error(f"AWS EC2 API error during scan: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during EC2 scan: {e}")

    return all_findings


def get_ec2_inventory() -> Dict[str, Any]:
    """
    Retrieves summary metadata of EC2 instances and security groups.
    """
    inventory = {"instances": [], "security_groups": []}
    try:
        ec2 = boto3.client("ec2")
        instances_resp = ec2.describe_instances()
        for res in instances_resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                inventory["instances"].append({
                    "id": inst.get("InstanceId"),
                    "type": inst.get("InstanceType"),
                    "state": inst.get("State", {}).get("Name"),
                    "public_ip": inst.get("PublicIpAddress", "N/A"),
                    "launch_time": str(inst.get("LaunchTime", "N/A")),
                })

        sgs_resp = ec2.describe_security_groups()
        for sg in sgs_resp.get("SecurityGroups", []):
            inventory["security_groups"].append({
                "id": sg.get("GroupId"),
                "name": sg.get("GroupName"),
                "description": sg.get("Description", ""),
                "vpc_id": sg.get("VpcId", "N/A"),
                "rules_count": len(sg.get("IpPermissions", [])),
            })
    except Exception as e:
        logger.warning(f"Failed to fetch EC2 inventory: {e}")

    return inventory