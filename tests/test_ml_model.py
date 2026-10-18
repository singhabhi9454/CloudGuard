"""
CloudGuard Machine Learning Unit Tests
Covers feature extraction, input normalization, model loading,
prediction outputs, missing model handling, and API integration.
Runs offline without requiring live AWS credentials.
"""
import unittest
import os
import sys
import tempfile
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# Bootstrap project paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ml_model.feature_extractor import (
    FEATURE_NAMES,
    extract_features_from_dict,
    extract_features_from_findings,
    features_to_dataframe,
)
from ml_model.predictor import (
    load_model,
    predict_risk,
    get_model_info,
    MODEL_PATH,
)
import backend.main as app_module


class TestFeatureExtractor(unittest.TestCase):
    def test_feature_names_integrity(self):
        self.assertEqual(len(FEATURE_NAMES), 13)
        self.assertIn("ssh_port_22_open", FEATURE_NAMES)
        self.assertIn("s3_public_access_block_disabled", FEATURE_NAMES)
        self.assertIn("iam_console_without_mfa", FEATURE_NAMES)
        self.assertIn("rds_publicly_accessible", FEATURE_NAMES)

    def test_extract_from_findings(self):
        mock_findings = [
            {"service": "EC2", "issue": "SSH port 22 is open to everyone", "risk": "HIGH"},
            {"service": "S3", "issue": "S3 bucket does not have Public Access Block configured", "risk": "HIGH"},
            {"service": "IAM", "issue": "IAM user has console access without Multi-Factor Authentication (MFA)", "risk": "HIGH"},
            {"service": "RDS", "issue": "RDS database is publicly accessible", "risk": "HIGH"},
        ]
        features = extract_features_from_findings(mock_findings)

        self.assertEqual(features["ssh_port_22_open"], 1)
        self.assertEqual(features["s3_public_access_block_disabled"], 1)
        self.assertEqual(features["iam_console_without_mfa"], 1)
        self.assertEqual(features["rds_publicly_accessible"], 1)
        # Unflagged features must be 0
        self.assertEqual(features["rdp_port_3389_open"], 0)
        self.assertEqual(features["rds_encryption_disabled"], 0)

    def test_extract_from_dict_and_aliases(self):
        input_dict = {
            "ssh_open": True,
            "rdp_port_3389": 0,
            "s3_pab_disabled": "yes",
            "mfa_disabled": 1,
            "random_irrelevant_key": 42,
        }
        features = extract_features_from_dict(input_dict)

        self.assertEqual(features["ssh_port_22_open"], 1)
        self.assertEqual(features["rdp_port_3389_open"], 0)
        self.assertEqual(features["s3_public_access_block_disabled"], 1)
        self.assertEqual(features["iam_console_without_mfa"], 1)
        self.assertEqual(features["all_traffic_open"], 0)

    def test_features_to_dataframe(self):
        features = {f: 1 for f in FEATURE_NAMES}
        df = features_to_dataframe(features)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(df.shape, (1, 13))
        self.assertEqual(list(df.columns), FEATURE_NAMES)


class TestModelPredictor(unittest.TestCase):
    def test_model_loading_and_type(self):
        model, metadata = load_model()
        self.assertIsInstance(model, RandomForestClassifier)
        self.assertIn("classes", metadata)
        self.assertEqual(set(metadata["classes"]), {"HIGH", "LOW", "MEDIUM"})

    def test_missing_model_file_handling(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_path = os.path.join(tmpdir, "nonexistent.joblib")
            with self.assertRaises(FileNotFoundError):
                load_model(model_path=fake_path)

    def test_predict_risk_high_vulnerability(self):
        high_config = {"ssh_port_22_open": 1, "all_traffic_open": 1}
        result = predict_risk(high_config)

        self.assertEqual(result["predicted_risk"], "HIGH")
        self.assertIn("class_probabilities", result)
        probs = result["class_probabilities"]
        self.assertIn("HIGH", probs)
        self.assertIn("LOW", probs)
        self.assertIn("MEDIUM", probs)
        self.assertAlmostEqual(sum(probs.values()), 1.0, places=2)
        self.assertGreater(result["confidence"], 0.0)
        self.assertIn("disclaimer", result)
        self.assertEqual(result["model_version"], "1.0.0")

    def test_predict_risk_low_hardened(self):
        clean_config = {f: 0 for f in FEATURE_NAMES}
        result = predict_risk(clean_config)

        self.assertEqual(result["predicted_risk"], "LOW")
        self.assertGreater(result["class_probabilities"]["LOW"], result["class_probabilities"]["HIGH"])

    def test_predict_risk_medium_hygiene(self):
        medium_config = {"s3_encryption_disabled": 1, "iam_access_key_age_over_90d": 1}
        result = predict_risk(medium_config)

        self.assertEqual(result["predicted_risk"], "MEDIUM")
        self.assertGreater(result["class_probabilities"]["MEDIUM"], 0.5)

    def test_get_model_info(self):
        info = get_model_info()
        self.assertEqual(info["status"], "ready")
        self.assertEqual(info["model_version"], "1.0.0")
        self.assertIn("accuracy", info["metrics"])
        self.assertGreater(info["metrics"]["accuracy"], 0.85)


class TestFastAPIIntegration(unittest.TestCase):
    def test_predict_risk_endpoint(self):
        payload = {"ssh_port_22_open": 1}
        res = app_module.predict_risk_endpoint(payload)

        self.assertIn("predicted_risk", res)
        self.assertIn("class_probabilities", res)
        self.assertIn("model_version", res)
        self.assertEqual(res["predicted_risk"], "HIGH")

    def test_get_ml_model_info_endpoint(self):
        res = app_module.get_ml_model_info()
        self.assertEqual(res["status"], "ready")
        self.assertEqual(res["model_version"], "1.0.0")
        self.assertIn("features", res)
        self.assertIn("metrics", res)

    def test_predict_scan_risk_endpoint(self):
        res = app_module.predict_scan_risk_endpoint()
        self.assertIn("ml_prediction", res)
        self.assertIn("rule_based_evaluation", res)
        self.assertIn("predicted_risk", res["ml_prediction"])
        self.assertIn("score", res["rule_based_evaluation"])


if __name__ == "__main__":
    unittest.main()
