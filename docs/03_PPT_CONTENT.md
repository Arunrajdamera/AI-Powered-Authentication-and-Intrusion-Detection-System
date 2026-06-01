# 15-Slide PPT Content

## Slide 1: Title Slide
AI-Driven SIEM Application with Random Forest Based Intrusion Detection  
B.Tech Project  
Presented by: [Your Name]  
Department: [Department Name]  
Institution: [College Name]

## Slide 2: Problem Statement
- Authentication attacks are common in web applications.
- Basic login systems do not provide enough security visibility.
- Manual log review is slow and inefficient.
- There is a need for intelligent login monitoring and alerting.

## Slide 3: Objectives
- Build a secure Flask authentication system.
- Record login telemetry and audit logs.
- Detect suspicious authentication activity.
- Train and integrate a Random Forest IDS model.
- Provide admin dashboard, alerts, and CSV exports.

## Slide 4: Existing System
- Simple credential verification.
- Limited or no login analytics.
- No automated risk classification.
- No alert resolution workflow.
- No centralized security dashboard.

## Slide 5: Proposed System
- Web-based SIEM for authentication analytics.
- Role-based admin and user dashboards.
- Failed login tracking and lockout.
- ML-based IDS prediction.
- CSV export for investigation evidence.

## Slide 6: System Architecture
Place the architecture diagram from `docs/02_DIAGRAMS.md`.

Speaker note: Explain browser, Flask app, database, security service, IDS predictor, model training pipeline, and CSV reporting.

## Slide 7: Technology Stack
- Python
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- SQLite
- Scikit-learn
- Pandas, NumPy, Joblib
- Flask-Limiter

## Slide 8: Database Design
Place the ER diagram from `docs/02_DIAGRAMS.md`.

Mention tables:
- users
- roles
- login_logs
- audit_logs
- security_alerts

## Slide 9: Core Modules
- Authentication Module
- User and Role Module
- Login Telemetry Module
- Security Alert Module
- Audit Log Module
- IDS Prediction Module
- Admin Dashboard Module
- CSV Reporting Module

## Slide 10: Random Forest IDS Model
- Input features:
  - Login hour
  - Previous failed attempts
  - Suspicious IP flag
  - Country mismatch flag
  - New device flag
- Output classes:
  - Normal
  - Attack
- Model saved using Joblib.

## Slide 11: Security Features
- Password hashing
- CSRF protection
- Session expiry
- Login rate limiting
- Role-based access control
- Account lockout
- Audit logging
- Security alert resolution

## Slide 12: Screenshots
Add screenshots:
- Login page
- Registration page
- User dashboard
- Admin dashboard
- IDS prediction result

## Slide 13: Results
- Tests passing: 8
- Accuracy: 88.80%
- Precision: 66.06%
- Recall: 88.62%
- F1 Score: 75.69%
- CSV exports generated successfully.

## Slide 14: Future Scope
- Real-world authentication dataset.
- MFA for admin accounts.
- Email/SMS alert notifications.
- Advanced dashboards with charts.
- PostgreSQL deployment.
- IP reputation and geolocation APIs.

## Slide 15: Conclusion and Q&A
- The project integrates web security, SIEM monitoring, and ML-based IDS.
- It provides practical authentication analytics.
- It is scalable for future production-grade enhancements.
- Thank you.
