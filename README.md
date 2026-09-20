# AI-Powered Authentication and Intrusion Detection System

An AI-assisted cybersecurity platform that combines secure authentication, authentication telemetry, machine-learning-based intrusion detection, risk scoring, security alerting, audit logging, and SOC-style monitoring in a single Flask application.

## Live Deployment

**Production Application:**  
https://ai-powered-authentication-and-intrusion-detectio-production.up.railway.app/login

**GitHub Repository:**  
https://github.com/Arunrajdamera/AI-Powered-Authentication-and-Intrusion-Detection-System

---

## Project Overview

The system demonstrates how authentication security and intrusion detection can work together as a continuous security monitoring pipeline.

The application:

1. Authenticates users securely.
2. Records authentication telemetry.
3. Extracts security-relevant indicators.
4. Applies a machine-learning intrusion detection model.
5. Combines ML output with deterministic security indicators.
6. Calculates a derived risk score.
7. Assigns an alert severity.
8. Generates security alerts for suspicious activity.
9. Records security actions in an audit trail.
10. Presents the results through a SOC-style dashboard.

### Detection Pipeline

```text
User Authentication
        |
        v
Authentication Telemetry
        |
        v
Feature Extraction
        |
        v
Machine Learning Detection
        |
        +----------------------+
        |                      |
        v                      v
ML Classification       Security Indicators
        |                      |
        +----------+-----------+
                   |
                   v
             Risk Calculation
                   |
                   v
             Severity Engine
                   |
          +--------+--------+
          |                 |
          v                 v
    Security Alert      Audit Logging
          |
          v
      SOC Dashboard
```

---

## Key Features

### Secure Authentication

- User registration and login
- Password hashing
- Session management
- Role-based access control
- Login attempt monitoring
- Account protection mechanisms
- Password reset workflow
- CSRF protection
- Rate limiting

### AI-Assisted Intrusion Detection

- Random Forest based intrusion detection
- Authentication feature extraction
- ML classification
- ML risk scoring
- Suspicious authentication detection
- Behavioral indicators
- Derived risk calculation

### Security Monitoring

- SOC Command Center dashboard
- Authentication event monitoring
- Threat severity visualization
- Open security alerts
- Audit event tracking
- Recent security event monitoring
- IDS analysis interface

### Security Alerts

The application generates alerts based on authentication and detection signals, including:

- Repeated authentication attempts
- Suspicious authentication behavior
- Unknown account login attempts
- Unusual login time
- New or unrecognized devices
- ML-based suspicious activity

### Safe Demonstration Mode

The Threat Analysis interface includes controlled demonstration telemetry for safely testing the detection pipeline.

Available demonstrations include:

- Failed authentication burst
- New device login
- Off-hours login

These simulations generate local telemetry through the same processing pipeline without contacting external systems.

---

## Machine Learning

The project uses a Random Forest classifier as the baseline intrusion detection model.

### Baseline Model Metrics

| Metric | Result |
|---|---:|
| Accuracy | 88.80% |
| Precision | 66.06% |
| Recall | 88.62% |
| F1 Score | 75.69% |

These metrics represent the evaluated baseline model and should not be interpreted as production detection accuracy.

### Detection Flow

```text
Authentication Event
        |
        v
Feature Extraction
        |
        v
Random Forest Model
        |
        v
NORMAL / SUSPICIOUS
        |
        v
ML Risk Score
        |
        v
Deterministic Security Indicators
        |
        v
Derived Risk Score
        |
        v
NORMAL / LOW / MEDIUM / HIGH / CRITICAL
```

---

## Technology Stack

### Backend

- Python
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- Flask-Limiter
- Gunicorn

### Database

- PostgreSQL for production
- SQLite support for local development

### Machine Learning

- Scikit-learn
- Random Forest
- Pandas
- NumPy
- Joblib

### Security

- Password hashing
- CSRF protection
- Rate limiting
- Role-based access control
- Authentication monitoring
- Security alerting
- Audit logging
- Intrusion detection

### Deployment

- Railway
- PostgreSQL
- Gunicorn

---

## Project Architecture

```text
Browser
   |
   v
Flask Application
   |
   +----------------------+
   |          |           |
   v          v           v
Auth       SOC Dashboard  Threat Analysis
   |          |           |
   +----------+-----------+
              |
              v
       Security Service
              |
       +------+------+
       |             |
       v             v
   ML Predictor   Security Indicators
       |             |
       +------+------+
              |
              v
        Risk Calculation
              |
              v
      Security Event
              |
       +------+------+
       |             |
       v             v
 Security Alert   Audit Log
       |
       v
 PostgreSQL
```

---

## Database Architecture

The production deployment uses PostgreSQL.

The system contains the following main database entities:

```text
Users
  |
  +-- Roles
  |
  +-- Login Logs
  |
  +-- Security Events
  |
  +-- Security Alerts
  |
  +-- Audit Logs
  |
  +-- Password Reset Tokens
```

The application uses `extensions.py` for shared Flask extensions such as the database, login manager, CSRF protection, and rate limiter.

This keeps the application factory and models separated and avoids circular-import problems.

---

## Security Event Model

The system separates detection information into multiple layers.

### Authentication Result

```text
SUCCESS
FAILED
```

### ML Classification

```text
NORMAL
SUSPICIOUS
```

### Risk

The system derives a risk score using the ML output together with security indicators.

### Severity

```text
NORMAL
LOW
MEDIUM
HIGH
CRITICAL
```

### Alert State

```text
OPEN
RESOLVED
```

This separation makes individual detection decisions easier to investigate and audit.

---

## Audit Logging

Security-sensitive actions are recorded through the audit subsystem.

Examples include:

- Login events
- Logout events
- Authentication activity
- Safe telemetry simulations
- Administrative actions
- Security-related operations

The audit trail provides a record for investigating system activity.

---

## Password Recovery

The password recovery workflow uses security controls including:

- Expiring reset tokens
- Single-use reset tokens
- Hashed token storage
- Generic reset responses
- Secure password hashing

Sensitive configuration such as SMTP credentials, application secrets, and database credentials must remain in environment variables and must never be committed to GitHub.

---

## Production Deployment

The current application is deployed on Railway.

```text
Railway
   |
   +---- Flask Application
   |       |
   |       +---- Gunicorn
   |
   +---- PostgreSQL
```

The application reads the production database connection from `DATABASE_URL`.

Gunicorn runs the Flask application using:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT
```

---

## Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/Arunrajdamera/AI-Powered-Authentication-and-Intrusion-Detection-System.git
cd AI-Powered-Authentication-and-Intrusion-Detection-System
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a local `.env` file with the required application configuration.

At minimum, configure the application secret and database connection appropriate for your environment.

Never commit:

```text
.env
database credentials
SMTP passwords
API keys
private secrets
```

### 5. Run the application

```bash
python app.py
```

---

## Demonstration Workflow

For a complete project demonstration:

1. Open the live application.
2. Sign in with an authorized account.
3. Open the SOC Command Center.
4. Review authentication statistics.
5. Open Threat Analysis.
6. Run **Simulate failed burst**.
7. Run **Simulate new device**.
8. Run **Simulate off-hours login**.
9. Review the generated security events.
10. Observe ML classification and risk scores.
11. Review generated security alerts.
12. Review audit activity.
13. Demonstrate CSV export.
14. Demonstrate logout and role-based access.

---

## Example Detection

A controlled failed authentication burst can produce a result similar to:

```text
Authentication Result: FAILED
ML Classification: SUSPICIOUS
ML Risk: ~0.865
Derived Risk: 1.000
Severity: CRITICAL
```

The exact values depend on the generated telemetry and model output.

---

## Project Objectives

- Build a secure authentication platform.
- Collect authentication security telemetry.
- Apply machine learning to authentication behavior.
- Combine ML predictions with deterministic security indicators.
- Calculate actionable risk levels.
- Generate security alerts.
- Provide SOC-style security monitoring.
- Maintain an auditable security event history.
- Deploy the application using PostgreSQL and Gunicorn.

---

## Current Scope

This project focuses primarily on authentication telemetry and intrusion detection.

It is designed as a cybersecurity academic and portfolio project rather than a replacement for an enterprise SIEM or production SOC platform.

The model's performance depends on the training data, engineered features, detection logic, and deployment environment.

---

## Future Enhancements

Potential future improvements include:

- Multi-factor authentication
- IP reputation and threat-intelligence enrichment
- Redis-backed distributed rate limiting
- Real-world authentication telemetry datasets
- Expanded endpoint and network telemetry
- Advanced detection rules
- Analyst case management
- External SIEM integrations
- Model monitoring and retraining
- Detection model drift analysis
- Containerized deployment
- Expanded security analytics

---

## Author

**Damera Arunraj**

B.Tech Computer Science (Cyber Security)  
GITAM School of Technology, Visakhapatnam

**GitHub:**  
https://github.com/Arunrajdamera

**LinkedIn:**  
https://www.linkedin.com/in/arunrajdamera20/

---

## License

This project is intended for educational, research, academic, and portfolio demonstration purposes.
