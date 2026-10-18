# CloudGuard: AWS Cloud Security Assessment & Misconfiguration Scanner

CloudGuard is a full-stack Cloud Security Posture Management (CSPM) and misconfiguration scanner for Amazon Web Services (AWS). It automatically audits cloud environments across EC2, S3, IAM, and RDS against security best practices, computes an objective security score (0–100), executes Machine Learning risk prediction using Random Forest classification, presents real-time diagnostics on an interactive cybersecurity dashboard, supports safe human-confirmed auto-remediation, and generates executive PDF assessment reports.

---

## 1. Project Overview

Cloud infrastructure misconfigurations (such as public security groups, unencrypted storage, and excessive IAM privileges) are the leading cause of cloud security incidents. CloudGuard provides organizations and cloud administrators with an automated security assessment platform to:
- Detect misconfigured cloud resources in real time using the AWS SDK (`Boto3`).
- Classify risk levels based on industry-standard severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- Predict configuration risk posture using an integrated **Machine Learning Random Forest Classifier** (scikit-learn).
- Calculate a transparent 0–100 Cloud Security Health Score with weighted deductions.
- Inspect detailed remediation advice and execute safe, one-click human-approved remediations.
- Simulate hypothetical cloud configurations in an interactive "What-If" security playground.
- Export standardized PDF audit reports for compliance review.

---

## 2. Key Features

- **Live AWS Cloud Auditing**: Scans real AWS resources via the official Boto3 SDK without mock or fake data.
- **Multi-Service Security Coverage**:
  - **EC2**: Detects public ingress on Port 22 (SSH), Port 3389 (RDP), sensitive database ports, and all-traffic open rules.
  - **S3**: Inspects S3 Block Public Access configurations, bucket policy public exposure, and default encryption.
  - **IAM**: Audits console access without Multi-Factor Authentication (MFA), access keys older than 90 days, and excessive Administrator policies.
  - **RDS**: Identifies publicly accessible databases, unencrypted storage, and backup retention gaps.
- **Machine Learning Risk Prediction**:
  - Classifies infrastructure risk (`LOW`, `MEDIUM`, `HIGH`) using a trained `RandomForestClassifier` (scikit-learn).
  - Normalizes 13 multi-service configuration telemetry features across EC2, S3, IAM, and RDS.
  - Computes granular class probability distributions and confidence percentages.
  - Compares deterministic rule-based evaluation side-by-side with ML advisory predictions.
  - Features an interactive "What-If" simulator for real-time cloud hardening experiments.
- **Automated Security Scoring**: Evaluates cloud posture on a 100-point scale with transparent severity-based point deductions.
- **Safe Auto-Remediation**: Implements a strict Preview-Confirm-Apply protocol for risky ingress rules with rollback protection and automatic verification scans.
- **Historical Tracking & Trends**: Records all past audit runs and displays score trends over time in SQLite.
- **Executive PDF Reporting**: Generates downloadable PDF security assessment reports using pure Python.
- **Configurable Scheduler**: Supports Manual, Daily (24h), and Weekly background scan execution.
- **Cybersecurity Command Center UI**: Built with React, Vite, Framer Motion, and Lucide React with a dark cybersecurity visual design.

---

## 3. Architecture & Data Flow

```
┌──────────────────────────────────────────────────────────────┐
│                          AWS Cloud                           │
│           (EC2 / VPC, S3 Buckets, IAM Users, RDS)            │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼  Boto3 API Calls
┌──────────────────────────────────────────────────────────────┐
│                  CloudGuard Scanner Engine                   │
│         (ec2_scanner, s3_scanner, iam_scanner, rds)          │
└──────────────┬────────────────────────────────┬──────────────┘
               │                                │
               ▼ Resource Metadata              ▼ Raw Scan Findings
┌──────────────────────────────┐ ┌─────────────────────────────┐
│    Security Rules Engine     │ │   ML Feature Extractor      │
│  (ec2, s3, iam, rds rules)   │ │  (13 normalized features)   │
└──────────────┬───────────────┘ └──────────────┬──────────────┘
               │                                │
               ▼ Standard Findings              ▼ Feature Vector
┌──────────────────────────────┐ ┌─────────────────────────────┐
│   Deterministic Classifier   │ │   Random Forest Predictor   │
│   CRITICAL / HIGH / MED/ LOW │ │   LOW / MEDIUM / HIGH       │
│   Security Score (0 - 100)   │ │   Class Probabilities & Conf│
└──────────────┬───────────────┘ └──────────────┬──────────────┘
               │                                │
               └───────────────┬────────────────┘
                               │
                               ▼ Persist Scans, Findings & Telemetry
┌──────────────────────────────────────────────────────────────┐
│               SQLite Database (cloudguard.db)                │
│                 - scans table  |  findings table             │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼ REST APIs
┌──────────────────────────────────────────────────────────────┐
│                   FastAPI Backend Server                     │
│         (/scan, /findings, /predict-risk, /score, etc.)      │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼ HTTP / JSON
┌──────────────────────────────────────────────────────────────┐
│                    React Dashboard UI                        │
│    (Overview, Findings, ML Risk Prediction, Remediate, Logs) │
│       Framer Motion, Lucide Icons, Cyber Dark Theme          │
└──────────────────────────────────────────────────────────────┘
```

---

## 4. Technology Stack

- **Backend**: Python 3.9+, FastAPI, Uvicorn, Boto3, Pydantic
- **Machine Learning**: scikit-learn (RandomForestClassifier), pandas, NumPy, joblib
- **Frontend**: React 19, Vite, Framer Motion, Lucide React
- **Database**: SQLite 3 (`cloudguard.db`)
- **Cloud Provider**: Amazon Web Services (AWS)
- **Containerization**: Docker & Docker Compose
- **Testing**: Python `unittest` suite (28 comprehensive unit tests)

---

## 5. Project Directory Structure

```
CloudGuard/
├── backend/
│   ├── main.py                  # FastAPI REST routes and server (including ML endpoints)
│   └── Dockerfile               # Backend container definition
├── database/
│   └── database.py              # SQLite connection, schema migrations, and queries
├── ml_model/                    # Machine Learning Risk Prediction Module
│   ├── __init__.py              # ML package initialization
│   ├── dataset/
│   │   ├── generate_dataset.py  # Benchmark dataset generator (CIS AWS alignment)
│   │   └── security_configurations.csv # Labeled training dataset (750 samples)
│   ├── models/
│   │   ├── random_forest_risk_model.joblib # Serialized Random Forest model
│   │   └── model_metadata.json  # Model version, metrics, and feature importances
│   ├── feature_extractor.py     # Converts raw AWS findings into 13 model features
│   ├── predictor.py             # Model inference, probabilities, and advisory generation
│   └── train_model.py           # Stratified model training & evaluation pipeline
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Main React dashboard & ML Risk Prediction UI
│   │   ├── App.css              # Cybersecurity styling & animations
│   │   ├── index.css            # Base stylesheet
│   │   └── main.jsx             # React entrypoint
│   ├── package.json             # Frontend dependencies
│   ├── vite.config.js           # Vite build configuration
│   └── Dockerfile               # Multi-stage frontend container
├── rules/
│   ├── ec2_rules.py             # EC2 security rules & port checks
│   ├── s3_rules.py              # S3 public access & encryption rules
│   ├── iam_rules.py             # IAM MFA & access key rules
│   ├── rds_rules.py             # RDS public database rules
│   └── common_rules.py          # Shared CIDR and age helpers
├── scanner/
│   ├── finding.py               # Standardized finding schema constructor
│   ├── security_score.py        # 100-point security score calculator
│   ├── ec2_scanner.py           # EC2 instance & SG scanner
│   ├── s3_scanner.py            # Amazon S3 bucket scanner
│   ├── iam_scanner.py           # IAM user & credentials scanner
│   ├── rds_scanner.py           # Amazon RDS instance scanner
│   ├── main_scanner.py          # Orchestrator & CLI runner
│   ├── remediation.py           # Safe auto-remediation engine
│   ├── scheduler.py             # Background scan scheduler
│   └── alerts.py                # Alert rules and optional SMTP dispatcher
├── reports/
│   └── pdf_generator.py         # Standards-compliant PDF report builder
├── tests/
│   ├── test_rules_and_scanner.py# Unit tests for scanner rules and scoring (15 tests)
│   └── test_ml_model.py         # Unit tests for ML extraction, inference & APIs (13 tests)
├── docker-compose.yml           # Full-stack Docker deployment
├── requirements.txt             # Python dependencies
└── README.md                    # Project documentation
```

---

## 6. AWS Services Covered

1. **Amazon EC2**: Audits Security Groups attached to running instances and standalone VPC groups for unrestricted ingress (Port 22 SSH, Port 3389 RDP, Port 23 Telnet, sensitive database ports, and 0.0.0.0/0 all-traffic).
2. **Amazon S3**: Checks whether S3 Block Public Access is active across all 4 controls (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) and checks default SSE-S3 encryption.
3. **AWS IAM**: Identifies console users lacking Multi-Factor Authentication (MFA), active access keys older than 90 days, and directly attached `AdministratorAccess` policies.
4. **Amazon RDS**: Detects publicly accessible database instances and unencrypted storage.

---

## 7. Machine Learning Risk Prediction Module

### 7.1 Architecture & Role
The Machine Learning module **supplements** CloudGuard's deterministic security rules engine. While rule-based scoring executes rigid Boolean checks for specific misconfigurations, the Random Forest model analyzes compound, multi-service configuration vectors to estimate overall configuration risk posture (`LOW`, `MEDIUM`, `HIGH`) along with calibrated class probability distributions.

> **Governance Principle**: ML predictions in CloudGuard act strictly as advisory indicators. They do not replace authoritative security rule findings or automated compliance controls.

### 7.2 Features Extracted (13 Normalized Features)
The `feature_extractor.py` module converts both live AWS scanner findings and manual simulator payloads into 13 binary/integer numerical features:

| Feature Name | Description | Value Type |
|---|---|---|
| `ssh_port_22_open` | Public ingress on SSH Port 22 (`0.0.0.0/0`) | `0` or `1` |
| `rdp_port_3389_open` | Public ingress on RDP Port 3389 (`0.0.0.0/0`) | `0` or `1` |
| `all_traffic_open` | Unrestricted all-traffic ingress rule (`0.0.0.0/0`) | `0` or `1` |
| `sensitive_ports_open` | Sensitive database/admin ports open publicly (3306, 5432, 27017, etc.) | `0` or `1` |
| `s3_public_access_block_missing`| S3 Block Public Access is disabled on one or more buckets | `0` or `1` |
| `s3_encryption_missing` | S3 bucket lacks default server-side encryption | `0` or `1` |
| `s3_bucket_policy_public` | S3 bucket policy grants public read/write to `*` | `0` or `1` |
| `iam_users_without_mfa` | IAM console user lacks active MFA device | `0` or `1` |
| `iam_access_key_age_over_90d` | IAM access key is older than 90 days without rotation | `0` or `1` |
| `iam_admin_privileges_attached` | IAM user has direct `AdministratorAccess` policy | `0` or `1` |
| `rds_publicly_accessible` | RDS database instance has `PubliclyAccessible=True` | `0` or `1` |
| `rds_storage_unencrypted` | RDS database instance storage is not encrypted at rest | `0` or `1` |
| `unrestricted_security_groups_count` | Total count of security groups with open 0.0.0.0/0 ingress | Integer ($\ge 0$) |

### 7.3 Model Training & Benchmark Evaluation
The model is trained via `ml_model/train_model.py` on a balanced benchmark dataset of 750 configurations aligned with CIS AWS Foundations criteria:

- **Algorithm**: `RandomForestClassifier` (`n_estimators=100`, `max_depth=8`, `min_samples_split=4`, `class_weight='balanced'`, `random_state=42`)
- **Split**: 75% Training (562 samples), 25% Testing (188 samples) with stratified class preservation.
- **Evaluation Metrics (Held-Out Test Set)**:
  - **Accuracy**: `93.09%`
  - **Macro Precision**: `93.77%`
  - **Macro Recall**: `93.03%`
  - **Macro F1-Score**: `93.21%`
  - **Weighted F1-Score**: `93.07%`

#### Top Feature Importances
1. `all_traffic_open`: **15.0%**
2. `s3_bucket_policy_public`: **14.6%**
3. `rds_publicly_accessible`: **12.1%**
4. `iam_access_key_age_over_90d`: **9.0%**
5. `sensitive_ports_open`: **8.4%**

### 7.4 Retraining the Model
To re-run the benchmark data generation and model training pipeline:
```bash
source venv/bin/activate
python ml_model/dataset/generate_dataset.py
python ml_model/train_model.py
```
This updates `ml_model/models/random_forest_risk_model.joblib` and `ml_model/models/model_metadata.json`.

### 7.5 Technical Limitations & Advisory Disclaimer
1. **Synthetic Training Distribution**: The training dataset is synthetically synthesized based on CIS AWS Foundations benchmarks. It models configuration risk patterns but does not represent empirical telemetry across all enterprise cloud environments.
2. **Probabilistic Nature**: Class probabilities reflect model decision tree consensus, not a mathematical guarantee that an AWS environment is breach-proof or compromised.
3. **Defense-in-Depth**: Always rely on deterministic rule findings, least privilege policies, and VPC network segmentation in conjunction with ML predictions.

---

## 8. Installation & Setup

### Prerequisites
- Python 3.9 or higher
- Node.js 18+ and npm
- AWS CLI configured with active credentials

---

## 9. AWS Credentials Configuration

CloudGuard uses the standard AWS credential chain. **Never paste secret keys directly into source code files.**

Configure credentials using the official AWS CLI:
```bash
aws configure
```
Provide:
- AWS Access Key ID
- AWS Secret Access Key
- Default region name (e.g., `ap-south-1` or `us-east-1`)
- Default output format (`json`)

Alternatively, export environment variables:
```bash
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
export AWS_DEFAULT_REGION="ap-south-1"
```

---

## 10. Backend Setup & Run

1. Navigate to the project root and activate the Python virtual environment:
```bash
source venv/bin/activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Start the FastAPI backend server:
```bash
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```
Backend will be live at `http://127.0.0.1:8000` (API documentation available at `http://127.0.0.1:8000/docs`).

---

## 11. Frontend Setup & Run

1. Open a new terminal and navigate to the `frontend/` directory:
```bash
cd frontend
```

2. Install npm packages (if not already installed):
```bash
npm install
```

3. Start the Vite development server:
```bash
npm run dev
```
The dashboard will open at `http://localhost:5173`.

---

## 12. How to Perform a Security Scan & ML Analysis

1. Open `http://localhost:5173` in your browser.
2. Verify that the **AWS Connected** status indicator is green with your configured region.
3. Click the **Run Security Scan** button in the top navigation bar.
4. CloudGuard connects to AWS via Boto3, inspects EC2, S3, IAM, and RDS, runs the rules engine, stores findings in SQLite, and updates the security score.
5. Navigate to the **ML Risk Prediction** tab to inspect:
   - **Active Scan Risk Comparison**: Side-by-side comparison of deterministic Rule Risk vs. Random Forest ML Predicted Risk with confidence percentages.
   - **Interactive Risk Simulator**: Toggle individual security controls (SSH, RDP, S3 Public Access, MFA, RDS) or select quick presets (`Hardened Baseline`, `Current AWS Profile`, `Hygiene Gaps`, `Critical Perimeter`) to perform instant "What-If" risk forecasting.
   - **Model Telemetry**: Live metrics including model version, test accuracy, feature importances, and evaluation timestamp.

---

## 13. Security Rules & Scoring Logic

### Standard Finding Structure
Every scanner produces a standardized finding dictionary:
```json
{
  "service": "EC2",
  "resource": "sg-03f83b8b0d2a5c648",
  "issue": "SSH port 22 is open to everyone",
  "risk": "HIGH",
  "recommendation": "Allow SSH only from trusted IP addresses",
  "scan_time": "2026-10-07 03:48:14"
}
```

### Scoring Formula
The security score begins at **100** and applies weighted deductions for each finding:
- `CRITICAL`: **-30 points** (e.g., all-traffic open `0.0.0.0/0`, public bucket policy)
- `HIGH`: **-20 points** (e.g., SSH port 22 open to `0.0.0.0/0`, public RDS database, console user without MFA)
- `MEDIUM`: **-10 points** (e.g., access key > 90 days old, missing S3 default encryption)
- `LOW`: **-5 points** (e.g., minor configuration best-practice advisories)

The score is clamped with a floor of **0** so it never displays negative numbers.

---

## 14. Safe Auto-Remediation Protocol

To avoid administrative lockout and accidental cloud disruption:
1. **Never Automate Unsafely**: CloudGuard never alters AWS security rules without explicit human confirmation.
2. **Preview Fix**: Inspect the dry-run comparison showing the current rule (`0.0.0.0/0`) versus the proposed rule.
3. **Optional Trusted IP**: Administrators can optionally specify a trusted IP CIDR (e.g., `203.0.113.50/32`) or leave it blank to revoke public access entirely.
4. **Mandatory Confirmation**: Users must check the explicit authorization box before the `Confirm & Apply Fix` button unlocks.
5. **Auto-Verification**: Applying a fix triggers an automated re-scan to verify that the issue has been resolved.

---

## 15. REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Service root and status |
| `GET` | `/health` | AWS connection health, region, account ID, and DB status |
| `POST` | `/scan` | Triggers a live AWS scan, persists findings, and returns results |
| `GET` | `/findings` | Retrieves findings with optional filters (`service`, `risk`, `search`) |
| `GET` | `/findings/{id}` | Retrieves a single finding by ID |
| `GET` | `/scans` | Returns historical scan audit runs |
| `GET` | `/scans/{scan_id}` | Retrieves a specific scan run and its findings |
| `GET` | `/score` | Returns current security score and risk counts |
| `GET` | `/resources` | Discovers live AWS inventory (EC2, S3, IAM, RDS) |
| `POST` | `/remediate/preview` | Generates a dry-run remediation preview |
| `POST` | `/remediate/apply` | Applies human-confirmed remediation to AWS |
| `GET` | `/reports/pdf` | Generates and downloads a standardized PDF audit report |
| `GET` | `/alerts` | Lists active High and Critical alerts |
| `GET` | `/schedule` | Checks the automated scan schedule status |
| `POST` | `/schedule` | Updates the scan schedule (`MANUAL`, `DAILY`, `WEEKLY`) |
| `POST` | `/predict-risk` | Predicts risk level from a configuration feature payload via Random Forest ML |
| `POST` | `/predict-scan-risk`| Runs ML inference on live scan findings and produces side-by-side comparison |
| `GET` | `/ml-model/info` | Returns model version, metadata, test metrics, and feature importances |

### Example ML Prediction API Request & Response

#### Request:
```bash
curl -X POST http://127.0.0.1:8000/predict-risk \
  -H "Content-Type: application/json" \
  -d '{
    "ssh_port_22_open": 1,
    "rdp_port_3389_open": 0,
    "all_traffic_open": 0,
    "sensitive_ports_open": 0,
    "s3_public_access_block_missing": 0,
    "s3_encryption_missing": 0,
    "s3_bucket_policy_public": 0,
    "iam_users_without_mfa": 0,
    "iam_access_key_age_over_90d": 0,
    "iam_admin_privileges_attached": 0,
    "rds_publicly_accessible": 0,
    "rds_storage_unencrypted": 0,
    "unrestricted_security_groups_count": 1
  }'
```

#### Response:
```json
{
  "predicted_risk": "HIGH",
  "confidence": 0.576,
  "class_probabilities": {
    "HIGH": 0.576,
    "LOW": 0.346,
    "MEDIUM": 0.078
  },
  "model_version": "1.0.0",
  "features_used": {
    "ssh_port_22_open": 1,
    "rdp_port_3389_open": 0,
    "all_traffic_open": 0,
    "sensitive_ports_open": 0,
    "s3_public_access_block_missing": 0,
    "s3_encryption_missing": 0,
    "s3_bucket_policy_public": 0,
    "iam_users_without_mfa": 0,
    "iam_access_key_age_over_90d": 0,
    "iam_admin_privileges_attached": 0,
    "rds_publicly_accessible": 0,
    "rds_storage_unencrypted": 0,
    "unrestricted_security_groups_count": 1
  },
  "disclaimer": "This prediction is generated by a Machine Learning model (Random Forest) trained on security configuration patterns. It is an advisory assessment and does not constitute a guarantee of system security."
}
```

---

## 16. Running with Docker

CloudGuard includes multi-container Docker Compose support:

```bash
docker-compose up --build
```

- Host AWS credentials are safe: mounted read-only via `~/.aws:/root/.aws:ro`.
- SQLite database is persisted via `./cloudguard.db:/app/cloudguard.db`.
- Backend accessible at `http://localhost:8000`.
- Frontend accessible at `http://localhost:5173`.

---

## 17. Unit Testing

Run the complete automated test suite offline without requiring live AWS credentials:
```bash
python -m unittest discover tests
```
Outputs:
```
............................
----------------------------------------------------------------------
Ran 28 tests in 0.231s

OK
```
This runs:
1. `tests/test_rules_and_scanner.py`: 15 unit tests verifying EC2, S3, IAM, and RDS security rules, scoring engine, edge cases, and deduplication.
2. `tests/test_ml_model.py`: 13 unit tests verifying feature extraction, feature normalization, model loading, error handling for missing models, class probability calculations, input validation, and FastAPI ML endpoints.

---

## 18. Future Scope

- Multi-cloud posture assessment (Azure and Google Cloud Platform).
- CIS AWS Foundations Benchmark automated score mapping.
- Deep Learning / Neural Network model evaluation alongside Random Forest for anomaly detection.
- Slack & Microsoft Teams webhook alerting.
- Infrastructure as Code (Terraform / CloudFormation) misconfiguration scanning before deployment.
