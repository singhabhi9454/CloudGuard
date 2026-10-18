"""
CloudGuard Security Dataset Generator
Generates a structured, documented benchmark dataset of AWS configuration profiles
labeled as LOW, MEDIUM, or HIGH risk according to documented cloud security criteria.

DISCLAIMER:
This dataset is synthetic and modeled after CIS AWS Foundations Benchmark rules
and CloudGuard risk assessment criteria. It serves as a controlled benchmark for
evaluating classification performance and does not represent empirical real-world
cloud tenant telemetry.
"""
import os
import random
import pandas as pd
import numpy as np

# Ensure reproducible generation
random.seed(42)
np.random.seed(42)

FEATURE_COLUMNS = [
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


def determine_risk_label(row: dict) -> str:
    """
    Applies deterministic, documented security risk criteria:
    - HIGH: Direct external exposure of management/data protocols (SSH/RDP open,
            all traffic open, public DB, public S3 policy, or admin console without MFA).
    - MEDIUM: Defense-in-depth gaps, stale credentials, missing encryption, or backup gaps.
    - LOW: Hardened, compliant configurations adhering to least privilege and private network isolation.
    """
    # Critical perimeter risks -> HIGH
    is_perimeter_exposed = (
        row["ssh_port_22_open"] == 1
        or row["rdp_port_3389_open"] == 1
        or row["all_traffic_open"] == 1
        or row["rds_publicly_accessible"] == 1
        or row["s3_bucket_policy_public"] == 1
        or (row["iam_console_without_mfa"] == 1 and row["iam_admin_policy_attached"] == 1)
        or (row["sensitive_ports_open"] == 1 and row["ssh_port_22_open"] == 1)
    )

    if is_perimeter_exposed:
        return "HIGH"

    # Count configuration hygiene & defense-in-depth issues
    hygiene_issues = [
        row["sensitive_ports_open"],
        row["s3_public_access_block_disabled"],
        row["s3_encryption_disabled"],
        row["iam_console_without_mfa"],
        row["iam_access_key_age_over_90d"],
        row["iam_admin_policy_attached"],
        row["rds_encryption_disabled"],
        row["rds_backup_disabled"],
    ]
    hygiene_count = sum(hygiene_issues)

    if hygiene_count >= 1:
        # If multiple defense-in-depth weaknesses accumulate, classify as HIGH or MEDIUM
        if hygiene_count >= 3 or (row["iam_console_without_mfa"] == 1 and row["s3_public_access_block_disabled"] == 1):
            return "HIGH"
        return "MEDIUM"

    return "LOW"


def generate_benchmark_dataset(num_samples: int = 750) -> pd.DataFrame:
    """
    Generates diverse samples across three architectural archetypes:
    1. Fully hardened cloud environments (LOW)
    2. Defense-in-depth hygiene and compliance gaps (MEDIUM)
    3. Severe perimeter and administrative exposures (HIGH)
    """
    data = []

    # Archetype 1: Hardened / Compliant configurations (Target: ~260 samples)
    for _ in range(num_samples // 3):
        row = {col: 0 for col in FEATURE_COLUMNS}
        # Occasional minor single benign variation (e.g., non-admin key aging)
        if random.random() < 0.05:
            # Stays low if no other issue
            pass
        data.append(row)

    # Archetype 2: Medium-risk hygiene gaps (Target: ~250 samples)
    for _ in range(num_samples // 3):
        row = {col: 0 for col in FEATURE_COLUMNS}
        # Pick 1 or 2 medium flaws
        flaw_pool = [
            "s3_encryption_disabled",
            "s3_public_access_block_disabled",
            "iam_access_key_age_over_90d",
            "iam_admin_policy_attached",
            "rds_encryption_disabled",
            "rds_backup_disabled",
            "sensitive_ports_open",
        ]
        num_flaws = random.choice([1, 2])
        chosen_flaws = random.sample(flaw_pool, num_flaws)
        for flaw in chosen_flaws:
            row[flaw] = 1
        data.append(row)

    # Archetype 3: High-risk perimeter exposures (Target: ~240 samples)
    high_flaw_pool = [
        "ssh_port_22_open",
        "rdp_port_3389_open",
        "all_traffic_open",
        "rds_publicly_accessible",
        "s3_bucket_policy_public",
        "iam_console_without_mfa",
    ]
    secondary_flaw_pool = [
        "s3_encryption_disabled",
        "s3_public_access_block_disabled",
        "iam_admin_policy_attached",
        "rds_encryption_disabled",
    ]

    for _ in range(num_samples // 3):
        row = {col: 0 for col in FEATURE_COLUMNS}
        # Guarantee at least 1 high perimeter flaw
        primary_flaw = random.choice(high_flaw_pool)
        row[primary_flaw] = 1

        # Optionally add secondary flaws
        if random.random() < 0.5:
            sec_flaw = random.choice(secondary_flaw_pool)
            row[sec_flaw] = 1
        data.append(row)

    # Convert to DataFrame and compute labels
    df = pd.DataFrame(data)
    df["risk_label"] = df.apply(determine_risk_label, axis=1)

    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    return df


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_path = os.path.join(base_dir, "dataset", "security_configurations.csv")

    df = generate_benchmark_dataset(num_samples=750)
    df.to_csv(output_path, index=False)

    print(f"Generated {len(df)} samples into {output_path}")
    print("\nClass distribution:")
    print(df["risk_label"].value_counts(normalize=True).round(3))
