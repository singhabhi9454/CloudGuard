"""
CloudGuard Common Rules & Helpers
Shared utilities for IP range analysis, sensitive port detection, and age calculations.
"""
from datetime import datetime, timezone
from typing import Optional, Set

# Public internet CIDRs
PUBLIC_CIDRS: Set[str] = {"0.0.0.0/0", "::/0"}

# Sensitive management and database ports
SENSITIVE_PORTS = {
    21: ("FTP", "HIGH"),
    22: ("SSH", "HIGH"),
    23: ("Telnet", "HIGH"),
    3389: ("RDP", "HIGH"),
    3306: ("MySQL", "HIGH"),
    5432: ("PostgreSQL", "HIGH"),
    27017: ("MongoDB", "HIGH"),
    6379: ("Redis", "HIGH"),
    9200: ("Elasticsearch", "HIGH"),
}


def is_cidr_public(cidr: str) -> bool:
    """Returns True if the given CIDR represents unrestricted public access."""
    return cidr in PUBLIC_CIDRS


def is_port_in_range(port: int, from_port: Optional[int], to_port: Optional[int]) -> bool:
    """Checks if a target port falls within the specified rule port bounds."""
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port


def days_since(dt: Optional[datetime]) -> int:
    """Calculates days elapsed since a datetime object, handling timezone awareness."""
    if not dt:
        return 0
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (now - dt).days)
