"""
CloudGuard Unit Test Suite
Covers security rules, risk classification, scoring algorithm, finding creation, and remediation preview.
Runs entirely offline without requiring live AWS credentials.
"""
import unittest
import os
import sys
from datetime import datetime, timezone, timedelta

# Bootstrap project path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scanner.finding import create_finding
from scanner.security_score import calculate_security_score
from rules.ec2_rules import check_security_group_rules
from rules.s3_rules import check_s3_bucket
from rules.iam_rules import check_iam_user
from rules.rds_rules import check_rds_instance
from scanner.remediation import preview_remediation


class TestFindingCreation(unittest.TestCase):
    def test_create_finding_schema(self):
        f = create_finding(
            service="EC2",
            resource="sg-test1234",
            issue="SSH port 22 is open to everyone",
            risk="HIGH",
            recommendation="Allow SSH only from trusted IP addresses",
        )
        self.assertEqual(f["service"], "EC2")
        self.assertEqual(f["resource"], "sg-test1234")
        self.assertEqual(f["issue"], "SSH port 22 is open to everyone")
        self.assertEqual(f["risk"], "HIGH")
        self.assertEqual(f["recommendation"], "Allow SSH only from trusted IP addresses")
        self.assertIn("scan_time", f)

    def test_risk_normalization(self):
        f1 = create_finding("S3", "my-bucket", "Test issue", "high", "Fix it")
        self.assertEqual(f1["risk"], "HIGH")

        f2 = create_finding("IAM", "alice", "Test issue", "invalid_risk", "Fix it")
        self.assertEqual(f2["risk"], "MEDIUM")


class TestSecurityScore(unittest.TestCase):
    def test_perfect_score(self):
        result = calculate_security_score([])
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["critical"], 0)
        self.assertEqual(result["high"], 0)

    def test_deductions_and_breakdown(self):
        findings = [
            create_finding("EC2", "sg-1", "SSH open", "HIGH", "Restrict"),
            create_finding("S3", "b-1", "No PAB", "HIGH", "Enable"),
            create_finding("IAM", "u-1", "Old key", "MEDIUM", "Rotate"),
            create_finding("EC2", "sg-2", "Default sg", "LOW", "Clean"),
            create_finding("EC2", "sg-3", "All open", "CRITICAL", "Revoke"),
        ]
        # 100 - 20(HIGH) - 20(HIGH) - 10(MED) - 5(LOW) - 30(CRIT) = 15
        result = calculate_security_score(findings)
        self.assertEqual(result["score"], 15)
        self.assertEqual(result["total"], 5)
        self.assertEqual(result["critical"], 1)
        self.assertEqual(result["high"], 2)
        self.assertEqual(result["medium"], 1)
        self.assertEqual(result["low"], 1)

    def test_score_floor_zero(self):
        # 4 Critical findings = -120 points -> must clamp to 0
        findings = [create_finding("EC2", f"sg-{i}", "Crit", "CRITICAL", "Fix") for i in range(4)]
        result = calculate_security_score(findings)
        self.assertEqual(result["score"], 0)


class TestEC2Rules(unittest.TestCase):
    def test_ssh_open_to_world(self):
        permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ]
        findings = check_security_group_rules(permissions, "sg-open-ssh")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["service"], "EC2")
        self.assertEqual(findings[0]["issue"], "SSH port 22 is open to everyone")
        self.assertEqual(findings[0]["risk"], "HIGH")

    def test_rdp_open_to_world(self):
        permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ]
        findings = check_security_group_rules(permissions, "sg-open-rdp")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["issue"], "RDP port 3389 is open to everyone")
        self.assertEqual(findings[0]["risk"], "HIGH")

    def test_trusted_ip_produces_no_finding(self):
        permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "192.168.1.100/32"}],
            }
        ]
        findings = check_security_group_rules(permissions, "sg-trusted")
        self.assertEqual(len(findings), 0)

    def test_all_traffic_unrestricted(self):
        permissions = [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ]
        findings = check_security_group_rules(permissions, "sg-all-traffic")
        self.assertTrue(any(f["risk"] == "CRITICAL" for f in findings))


class TestS3Rules(unittest.TestCase):
    def test_s3_missing_pab(self):
        bucket_data = {
            "Name": "public-bucket-test",
            "PublicAccessBlock": {},
            "Encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
        }
        findings = check_s3_bucket(bucket_data)
        self.assertTrue(any("Public Access Block" in f["issue"] for f in findings))
        self.assertEqual(findings[0]["service"], "S3")

    def test_s3_secure_bucket(self):
        bucket_data = {
            "Name": "secure-bucket-test",
            "PublicAccessBlock": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "Encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
            "PolicyStatus": {"IsPublic": False},
        }
        findings = check_s3_bucket(bucket_data)
        self.assertEqual(len(findings), 0)


class TestIAMRules(unittest.TestCase):
    def test_iam_console_without_mfa(self):
        user_data = {
            "UserName": "admin_user",
            "HasLoginProfile": True,
            "HasMFA": False,
            "AccessKeys": [],
            "AttachedPolicies": [],
        }
        findings = check_iam_user(user_data)
        self.assertTrue(any("MFA" in f["issue"] for f in findings))
        self.assertEqual(findings[0]["service"], "IAM")

    def test_iam_old_access_key(self):
        old_date = datetime.now(timezone.utc) - timedelta(days=120)
        user_data = {
            "UserName": "dev_user",
            "HasLoginProfile": False,
            "HasMFA": False,
            "AccessKeys": [
                {
                    "AccessKeyId": "AKIA1234567890",
                    "Status": "Active",
                    "CreateDate": old_date,
                }
            ],
            "AttachedPolicies": [],
        }
        findings = check_iam_user(user_data)
        self.assertTrue(any("90-day threshold" in f["issue"] for f in findings))
        self.assertEqual(findings[0]["risk"], "MEDIUM")


class TestRDSRules(unittest.TestCase):
    def test_rds_public_access(self):
        db_data = {
            "DBInstanceIdentifier": "prod-db-1",
            "PubliclyAccessible": True,
            "StorageEncrypted": True,
            "BackupRetentionPeriod": 7,
            "AutoMinorVersionUpgrade": True,
            "MultiAZ": True,
        }
        findings = check_rds_instance(db_data)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["service"], "RDS")
        self.assertEqual(findings[0]["issue"], "RDS database is publicly accessible")
        self.assertEqual(findings[0]["risk"], "HIGH")

    def test_rds_unencrypted_storage(self):
        db_data = {
            "DBInstanceIdentifier": "dev-db-1",
            "PubliclyAccessible": False,
            "StorageEncrypted": False,
            "BackupRetentionPeriod": 7,
            "AutoMinorVersionUpgrade": True,
            "MultiAZ": True,
        }
        findings = check_rds_instance(db_data)
        self.assertTrue(any("encrypted" in f["issue"].lower() for f in findings))


if __name__ == "__main__":
    unittest.main()
