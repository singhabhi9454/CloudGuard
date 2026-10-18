"""
CloudGuard Machine Learning Model Trainer
Trains a reproducible Random Forest Classifier to predict AWS configuration risk categories.
Saves model artifacts, feature metadata, and evaluation metrics for deployment.
"""
import os
import sys
import json
from datetime import datetime
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

# Bootstrap project paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ml_model.feature_extractor import FEATURE_NAMES

MODEL_VERSION = "1.0.0"
DATASET_PATH = os.path.join(BASE_DIR, "ml_model", "dataset", "security_configurations.csv")
MODELS_DIR = os.path.join(BASE_DIR, "ml_model", "models")
MODEL_OUTPUT_PATH = os.path.join(MODELS_DIR, "random_forest_risk_model.joblib")
METADATA_OUTPUT_PATH = os.path.join(MODELS_DIR, "model_metadata.json")


def load_and_validate_dataset(csv_path: str) -> pd.DataFrame:
    """Loads and validates the training dataset."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}. Run generate_dataset.py first.")

    df = pd.read_csv(csv_path)

    # Validate required columns
    missing_cols = [col for col in FEATURE_NAMES if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Dataset missing required feature columns: {missing_cols}")

    if "risk_label" not in df.columns:
        raise ValueError("Dataset missing 'risk_label' target column.")

    # Check for missing values
    null_counts = df.isnull().sum()
    if null_counts.any():
        print("Warning: Missing values found. Dropping rows with nulls.")
        df = df.dropna().reset_index(drop=True)

    print(f"Loaded {len(df)} validated configurations.")
    print("Class distribution:")
    print(df["risk_label"].value_counts())

    return df


def train_and_evaluate_model():
    """Trains the Random Forest model and saves artifacts."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    # 1. Load dataset
    df = load_and_validate_dataset(DATASET_PATH)

    X = df[FEATURE_NAMES]
    y = df["risk_label"]

    # 2. Stratified train/test split (75% train, 25% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"\nTraining set size: {len(X_train)} | Test set size: {len(X_test)}")

    # 3. Initialize and train Random Forest Classifier
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
    )
    rf.fit(X_train, y_train)

    # 4. Evaluate on test set
    y_pred = rf.predict(X_test)

    acc = float(accuracy_score(y_test, y_pred))
    prec_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))

    prec_weighted = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec_weighted = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    classes = rf.classes_.tolist()
    conf_mat = confusion_matrix(y_test, y_pred, labels=classes).tolist()
    report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    # Feature importances
    feature_importances = {
        feat: round(float(imp), 4)
        for feat, imp in zip(FEATURE_NAMES, rf.feature_importances_)
    }
    # Sort by importance
    sorted_importances = dict(sorted(feature_importances.items(), key=lambda item: item[1], reverse=True))

    print("\n========================================================")
    print("      CLOUDGUARD ML RISK MODEL EVALUATION RESULTS       ")
    print("========================================================")
    print(f"Model:                 RandomForestClassifier (Version: {MODEL_VERSION})")
    print(f"Accuracy:              {acc:.4f} ({acc*100:.2f}%)")
    print(f"Macro Precision:       {prec_macro:.4f}")
    print(f"Macro Recall:          {rec_macro:.4f}")
    print(f"Macro F1-Score:        {f1_macro:.4f}")
    print(f"Weighted F1-Score:     {f1_weighted:.4f}")
    print("\nConfusion Matrix (Classes: {}):".format(classes))
    for row in conf_mat:
        print("  ", row)
    print("\nTop 5 Feature Importances:")
    for feat, imp in list(sorted_importances.items())[:5]:
        print(f"  - {feat}: {imp:.4f}")
    print("========================================================\n")

    # 5. Save model using joblib
    joblib.dump(rf, MODEL_OUTPUT_PATH)
    print(f"Model saved to: {MODEL_OUTPUT_PATH}")

    # 6. Save metadata
    metadata = {
        "model_version": MODEL_VERSION,
        "model_type": "RandomForestClassifier",
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "random_seed": 42,
        "features": FEATURE_NAMES,
        "classes": classes,
        "metrics": {
            "accuracy": round(acc, 4),
            "macro_precision": round(prec_macro, 4),
            "macro_recall": round(rec_macro, 4),
            "macro_f1": round(f1_macro, 4),
            "weighted_f1": round(f1_weighted, 4),
            "confusion_matrix": conf_mat,
            "classification_report": report_dict,
        },
        "feature_importances": sorted_importances,
        "dataset_info": {
            "total_samples": len(df),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "class_distribution": df["risk_label"].value_counts().to_dict(),
        },
    }

    with open(METADATA_OUTPUT_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"Metadata saved to: {METADATA_OUTPUT_PATH}")

    return rf, metadata


if __name__ == "__main__":
    train_and_evaluate_model()
