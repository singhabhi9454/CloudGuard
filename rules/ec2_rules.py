"""
CloudGuard EC2 Security Rules
Evaluates EC2 Security Group ingress configurations for sensitive port exposure.
"""
from typing import List, Dict, Any
from scanner.finding import create_finding
from rules.common_rules import is_cidr_public, SENSITIVE_PORTS


def check_security_group_rules(
    ip_permissions: List[Dict[str, Any]], resource_id: str
) -> List[Dict[str, Any]]:
    """
    Analyzes Security Group inbound rules for public misconfigurations.
    Preserves exact standard wording for baseline tests.
    """
    findings: List[Dict[str, Any]] = []
    seen_keys = set()

    for rule in ip_permissions:
        ip_protocol = str(rule.get("IpProtocol", "")).lower()
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

        # Collect IPv4 and IPv6 CIDR blocks
        cidrs = [ip_range.get("CidrIp") for ip_range in rule.get("IpRanges", []) if ip_range.get("CidrIp")]
        cidrs.extend([ipv6_range.get("CidrIpv6") for ipv6_range in rule.get("Ipv6Ranges", []) if ipv6_range.get("CidrIpv6")])

        for cidr in cidrs:
            if not is_cidr_public(cidr):
                continue

            # Rule 0: All traffic open to internet (-1 or 0-65535)
            if ip_protocol == "-1" or (from_port == 0 and to_port == 65535):
                dedup_key = (resource_id, "ALL_TRAFFIC", cidr)
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    findings.append(
                        create_finding(
                            service="EC2",
                            resource=resource_id,
                            issue=f"All traffic (all ports) open to everyone ({cidr})",
                            risk="CRITICAL",
                            recommendation="Restrict ingress to only necessary protocols and trusted IP ranges.",
                        )
                    )
                continue

            # Rule 1: SSH (Exact wording preserved)
            if from_port == 22 or (from_port is not None and to_port is not None and from_port <= 22 <= to_port):
                dedup_key = (resource_id, 22, cidr)
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    findings.append(
                        create_finding(
                            service="EC2",
                            resource=resource_id,
                            issue="SSH port 22 is open to everyone",
                            risk="HIGH",
                            recommendation="Allow SSH only from trusted IP addresses",
                        )
                    )

            # Rule 2: RDP (Exact wording preserved)
            if from_port == 3389 or (from_port is not None and to_port is not None and from_port <= 3389 <= to_port):
                dedup_key = (resource_id, 3389, cidr)
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    findings.append(
                        create_finding(
                            service="EC2",
                            resource=resource_id,
                            issue="RDP port 3389 is open to everyone",
                            risk="HIGH",
                            recommendation="Allow RDP only from trusted IP addresses",
                        )
                    )

            # Rule 3: Other sensitive ports (Databases, Telnet, FTP)
            for port, (name, risk_level) in SENSITIVE_PORTS.items():
                if port in (22, 3389):
                    continue
                if from_port == port or (from_port is not None and to_port is not None and from_port <= port <= to_port):
                    dedup_key = (resource_id, port, cidr)
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        findings.append(
                            create_finding(
                                service="EC2",
                                resource=resource_id,
                                issue=f"{name} port {port} is open to everyone ({cidr})",
                                risk=risk_level,
                                recommendation=f"Restrict {name} access to trusted internal IP ranges or VPN.",
                            )
                        )

    return findings