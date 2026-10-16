"""
CloudGuard Security Score Calculator
Calculates a 0-100 security score based on weighted deductions for misconfigurations.
"""
from typing import List, Dict, Any


def calculate_security_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes security score starting at 100 with deductions:
    - CRITICAL: -30
    - HIGH:     -20
    - MEDIUM:   -10
    - LOW:      -5

    Score is bounded between 0 and 100.
    Returns:
    {
        "score": int,
        "critical": int,
        "high": int,
        "medium": int,
        "low": int,
        "total": int
    }
    """
    score = 100
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for finding in findings:
        risk = (finding.get("risk") or "").upper().strip()

        if risk == "CRITICAL":
            score -= 30
            critical_count += 1
        elif risk == "HIGH":
            score -= 20
            high_count += 1
        elif risk == "MEDIUM":
            score -= 10
            medium_count += 1
        elif risk == "LOW":
            score -= 5
            low_count += 1

    if score < 0:
        score = 0

    return {
        "score": score,
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "total": len(findings),
    }