# CloudGuard: AWS Cloud Security Assessment & Misconfiguration Scanner

CloudGuard is a full-stack Cloud Security Posture Management (CSPM) and misconfiguration scanner for Amazon Web Services (AWS). It automatically audits cloud environments across EC2, S3, IAM, and RDS against security best practices, computes an objective security score (0–100), presents real-time diagnostics on a cybersecurity dashboard, supports safe human-confirmed auto-remediation, and generates PDF assessment reports.

---

## 1. Project Overview

Cloud infrastructure misconfigurations (such as public security groups and unencrypted storage) are the leading cause of cloud security incidents. CloudGuard provides organizations and cloud administrators with an automated security assessment tool to:
- Detect misconfigured cloud resources in real time using the AWS SDK (`Boto3`).
- Classify risk levels based on industry-standard severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- Calculate a transparent 0–100 Cloud Security Health Score with weighted deductions.
- Inspect detailed remediation advice and execute safe, one-click human-approved remediations.
- Export standardized PDF audit reports for compliance review.

---

## 2. Key Features

- **Live AWS Cloud Auditing**: Scans real AWS resources via the official Boto3 SDK without mock or fake data.
- **Multi-Service Coverage**:
  - **EC2**: Detects public ingress on Port 22 (SSH), Port 3389 (RDP), sensitive database ports, and all-traffic open rules.
  - **S3**: Inspects S3 Block Public Access configurations, bucket policy public exposure, and default encryption.
  - **IAM**: Audits console access without Multi-Factor Authentication (MFA), access keys older than 90 days, and excessive Administrator policies.
  - **RDS**: Identifies publicly accessible databases, unencrypted storage, and backup retention gaps.
- **Automated Security Scoring**: Evaluates cloud posture on a 100-point scale with transparent severity-based point deductions.
- **Safe Auto-Remediation**: Implements a strict Preview-Confirm-Apply protocol for risky ingress rules with rollback protection and automatic verification scans.
- **Historical Tracking & Trends**: Records all past audit runs and displays score trends over time in SQLite.
- **Executive PDF Reporting**: Generates downloadable PDF security assessment reports using pure Python.
- **Configurable Scheduler**: Supports Manual, Daily (24h), and Weekly background scan execution.
- **Cybersecurity Command Center UI**: Built with React, Vite, Framer Motion, and Lucide React with a dark cybersecurity visual design.

---

## 3. Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────┐
│                      AWS Cloud                          │
│        (EC2 / VPC, S3 Buckets, IAM Users, RDS)          │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼  Boto3 API Calls
┌─────────────────────────────────────────────────────────┐
│              CloudGuard Scanner Engine                  │
│       (ec2_scanner, s3_scanner, iam_scanner, rds)       │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼  Resource Metadata
┌─────────────────────────────────────────────────────────┐
│               Security Rules Engine                     │
│    (ec2_rules, s3_rules, iam_rules, rds_rules, common)  │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼  Standardized Findings
┌─────────────────────────────────────────────────────────┐
│         Risk Classifier & Security Score Engine         │
│          CRITICAL (-30) | HIGH (-20) | MED (-10)        │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼  Persist Scans & Findings
┌─────────────────────────────────────────────────────────┐
│                 SQLite Database (cloudguard.db)         │
│               - scans table  |  findings table          │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼  REST APIs
┌─────────────────────────────────────────────────────────┐
│                  FastAPI Backend Server                 │
│              (Endpoints: /scan, /findings, etc.)        │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼  HTTP / JSON
┌─────────────────────────────────────────────────────────┐
│                 React Dashboard UI                      │
│     (Framer Motion, Lucide Icons, Cyber Dark Theme)     │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Technology Stack

- **Backend**: Python 3.9+, FastAPI, Uvicorn, Boto3, Pydantic
- **Frontend**: React 19, Vite, Framer Motion, Lucide React
- **Database**: SQLite 3 (`cloudguard.db`)
- **Cloud Provider**: Amazon Web Services (AWS)
- **Containerization**: Docker & Docker Compose
- **Testing**: Python `unittest` suite (15 offline unit tests)

---

## 5. Project Directory Structure

```
CloudGuard/
├── backend/
│   ├── main.py                  # FastAPI REST routes and server
│   └── Dockerfile               # Backend container definition
├── database/
│   └── database.py              # SQLite connection, schema migrations, and queries
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Main React dashboard component
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
│   └── test_rules_and_scanner.py# Unit tests for rules and scoring
├── docker-compose.yml           # Full-stack Docker deployment
├── requirements.txt             # Python dependencies
└── README.md                    # Project documentation
```

---

## 6. AWS Services Covered

1. **Amazon EC2**: Audits Security Groups attached to running instances and standalone VPC groups for unrestricted ingress (Port 22 SSH, Port 3389 RDP, Port 23 Telnet, sensitive database ports).
2. **Amazon S3**: Checks whether S3 Block Public Access is active across all 4 controls (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) and checks default SSE-S3 encryption.
3. **AWS IAM**: Identifies console users lacking Multi-Factor Authentication (MFA), active access keys older than 90 days, and directly attached `AdministratorAccess` policies.
4. **Amazon RDS**: Detects publicly accessible database instances and unencrypted storage.

---

## 7. Installation & Setup

### Prerequisites
- Python 3.9 or higher
- Node.js 18+ and npm
- AWS CLI configured with active credentials

---

## 8. AWS Credentials Configuration

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

## 9. Backend Setup & Run

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

## 10. Frontend Setup & Run

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

## 11. How to Perform a Security Scan

1. Open `http://localhost:5173` in your browser.
2. Verify that the **AWS Connected** status indicator is green with your configured region.
3. Click the **Run Security Scan** button in the top navigation bar.
4. CloudGuard connects to AWS via Boto3, inspects EC2, S3, IAM, and RDS, runs the rules engine, stores findings in SQLite, updates the security score, and renders the results immediately.
5. Review the updated **Security Score**, **Risk Summary**, and **Findings Directory**.

---

## 12. Security Rules & Scoring Logic

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

## 13. Safe Auto-Remediation Protocol

To avoid administrative lockout and accidental cloud disruption:
1. **Never Automate Unsafely**: CloudGuard never alters AWS security rules without human confirmation.
2. **Preview Fix**: Inspect the dry-run comparison showing the current rule (`0.0.0.0/0`) versus the proposed rule.
3. **Optional Trusted IP**: Administrators can optionally specify a trusted IP CIDR (e.g., `203.0.113.50/32`) or leave it blank to revoke public access entirely.
4. **Mandatory Confirmation**: Users must check the explicit authorization box before the `Confirm & Apply Fix` button unlocks.
5. **Auto-Verification**: Applying a fix triggers an automated re-scan to verify that the issue has been resolved.

---

## 14. REST API Endpoints

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

---

## 15. Running with Docker

CloudGuard includes multi-container Docker Compose support:

```bash
docker-compose up --build
```

- Host AWS credentials are safe: mounted read-only via `~/.aws:/root/.aws:ro`.
- SQLite database is persisted via `./cloudguard.db:/app/cloudguard.db`.
- Backend accessible at `http://localhost:8000`.
- Frontend accessible at `http://localhost:5173`.

---

## 16. Unit Testing

Run the automated test suite offline without requiring live AWS credentials:
```bash
python -m unittest tests/test_rules_and_scanner.py
```
Outputs:
```
...............
----------------------------------------------------------------------
Ran 15 tests in 0.001s

OK
```

---

## 17. Future Scope

- Multi-cloud posture assessment (Azure and Google Cloud Platform).
- CIS AWS Foundations Benchmark automated score mapping.
- Slack & Microsoft Teams webhook alerting.
- Infrastructure as Code (Terraform / CloudFormation) misconfiguration scanning before deployment.
