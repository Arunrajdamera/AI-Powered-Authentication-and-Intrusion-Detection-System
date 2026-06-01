# B.Tech Project Report

## Title
AI-Driven Security Information and Event Management System with Random Forest Based Intrusion Detection for Authentication Analytics

## Abstract
The project presents a web-based Security Information and Event Management (SIEM) application designed to monitor authentication activity, identify suspicious login behavior, generate security alerts, and support administrative investigation. The system is developed using Python and Flask with SQLite as the database backend. It integrates a machine learning based Intrusion Detection System (IDS) using a Random Forest classifier trained on synthetic authentication telemetry features such as login hour, failed login count, suspicious IP indication, country mismatch, and new device usage.

The application provides secure user authentication, password hashing, CSRF protection, session management, login telemetry, audit logging, account lockout, admin-level alert handling, CSV export, and an IDS prediction interface that classifies activity as Normal or Attack. The Random Forest model achieved 88.80% accuracy, 66.06% precision, 88.62% recall, and 75.69% F1 score during validation. The project demonstrates how conventional web security controls and machine learning analytics can be combined to improve visibility into authentication-related threats.

## Introduction
Modern web applications face frequent authentication attacks, including brute-force attempts, credential stuffing, suspicious geographic access, and anomalous login behavior. Traditional login systems usually verify only credentials and do not provide enough visibility into repeated failures, suspicious patterns, or incident history. SIEM systems solve this problem by collecting logs, correlating security events, and helping administrators detect threats.

This project implements a compact academic SIEM platform focused on authentication analytics. It records login events, measures risk, generates alerts, and provides administrative tools for incident review. A Random Forest IDS model is integrated to classify login behavior using contextual features. The project is suitable for demonstrating secure software development, database-backed web applications, machine learning integration, and cybersecurity monitoring.

## Problem Statement
Authentication systems often lack automated monitoring and intelligent classification of suspicious login attempts. Without a centralized dashboard, administrators may not notice repeated failed logins, account lockouts, or anomalous access patterns. Manual log analysis is slow and error-prone. Therefore, there is a need for a secure web-based system that records authentication telemetry, applies machine learning based risk analysis, generates alerts, and provides administrative tools for monitoring and response.

## Objectives
- Develop a secure Flask web application with user registration, login, logout, and session management.
- Store users, roles, login telemetry, audit logs, and security alerts in SQLite.
- Implement password hashing, CSRF protection, and role-based admin access.
- Detect repeated failed login attempts and apply temporary account lockout.
- Generate security alerts for suspicious authentication events.
- Build a Random Forest IDS model for classifying login behavior.
- Provide an IDS prediction page with Normal and Attack output classes.
- Provide an admin dashboard with user list, alert tracking, and CSV exports.
- Validate core features using automated tests.

## Scope
The project focuses on authentication analytics and SIEM-style monitoring for web login activity. It does not attempt to monitor full network packets, endpoint telemetry, malware behavior, or cloud infrastructure logs. The IDS model is trained on synthetic authentication features, making the system appropriate for academic demonstration and future extension using real organizational telemetry.

## Existing System
In a basic authentication system, users enter credentials, and the system grants or denies access. Such systems may store successful or failed login entries, but many do not classify suspicious behavior or produce meaningful admin alerts. Manual review of logs is inefficient, especially when many attempts occur quickly. Existing simple login systems usually lack:

- ML-based risk scoring.
- Centralized security dashboard.
- Account lockout tracking.
- Exportable incident evidence.
- Audit trail for administrative actions.
- Alert resolution workflow.

## Proposed System
The proposed system combines Flask-based authentication with SIEM monitoring and Random Forest based IDS classification. Each login attempt is recorded with contextual telemetry. Failed attempts update account risk state and can trigger account lockout. Security alerts are visible in the admin dashboard and can be resolved by authorized administrators. The IDS prediction page allows classification of sample traffic as Normal or Attack.

## Technology Stack
- Python: Core programming language.
- Flask: Web framework and routing layer.
- Flask-SQLAlchemy: ORM and database access.
- Flask-Login: Session-based authentication.
- Flask-WTF: CSRF protection.
- SQLite: Lightweight relational database.
- Scikit-learn: Random Forest model training and prediction.
- Pandas and NumPy: Dataset preparation and feature processing.
- Joblib: Model serialization.
- Flask-Limiter: Login rate limiting.
- HTML templates: Server-rendered user interface.
- GitHub Actions: Automated test workflow.

## System Modules

### Authentication Module
Provides registration, login, logout, password validation, session creation, and failed-login handling. Passwords are stored as secure hashes rather than plain text.

### User and Role Module
Maintains users and roles. Admin users can access the centralized security dashboard, while standard users access personal telemetry.

### Login Telemetry Module
Stores each login attempt with user identity, IP address, user agent, country code, success status, risk score, suspicious indicators, and timestamp.

### Security Alert Module
Creates alert records for incidents such as brute-force threshold violations, high-risk authentication attempts, and unknown account login attempts.

### Audit Log Module
Records administrative and security-sensitive actions such as registration, successful login, logout, alert resolution, and admin seeding.

### IDS/ML Module
Generates a synthetic authentication dataset, trains a Random Forest classifier, stores model metrics, serializes the trained model, and classifies input activity as Normal or Attack.

### Admin Dashboard Module
Displays total users, login events, open alerts, audit logs, user list, alert list, resolution controls, and CSV export links.

### Reporting Module
Converts SIEM records into downloadable CSV snapshots for review and documentation.

## Database Design

### Main Tables
- roles: Stores role names and descriptions.
- users: Stores user accounts, password hashes, status, role, failed login count, and lockout information.
- login_logs: Stores authentication telemetry and IDS risk scores.
- audit_logs: Stores append-only administrative action history.
- security_alerts: Stores alert classification, severity, description, and resolution status.

## Implementation Summary
The system follows an application factory structure. Configuration is loaded from environment variables, and runtime folders are created automatically. Database initialization and admin seeding are handled through a separate script to keep deployment setup isolated from normal runtime. Flask-Login loads users using SQLAlchemy session access. The login route validates credentials, extracts telemetry features, calls the IDS predictor, records login logs, updates failed-login milestones, and creates alerts when needed.

The Random Forest model is trained using generated authentication samples. Each sample includes login hour, failed login count, suspicious IP flag, country mismatch flag, and new device flag. The trained model is saved as a Joblib artifact and used at runtime by the predictor class. If the model is unavailable, a deterministic fallback risk calculation prevents application failure.

## Testing
Automated unit tests validate the following:
- User and role creation.
- Password hashing.
- Required database tables.
- Weak password rejection.
- Successful login telemetry.
- Account lockout after failed attempts.
- Admin CSV export.
- Admin user list visibility.
- IDS prediction page classification for Normal and Attack cases.

Current validation:

| Metric | Value |
|---|---:|
| Tests Passing | 8 |
| Accuracy | 88.80% |
| Precision | 66.06% |
| Recall | 88.62% |
| F1 Score | 75.69% |

## Results
The implemented system successfully authenticates users, logs security telemetry, protects routes using role-based checks, records failed login attempts, locks accounts after repeated failures, raises security alerts, exports records to CSV, and classifies IDS samples as Normal or Attack. The Random Forest model provides strong recall, which is useful in security monitoring where missed attacks can be more harmful than false positives.

## Security Features
- Password hashing using Werkzeug security functions.
- CSRF protection for POST forms.
- Session-based authentication.
- Session lifetime configuration.
- Role-based admin authorization.
- Login rate limiting.
- Failed login counting and lockout.
- Audit logging of security-sensitive events.
- Alert resolution tracking.
- CSV export for investigation records.

## Limitations
- The IDS model is trained on synthetic data rather than real enterprise authentication logs.
- The web interface is intentionally simple and can be improved visually.
- SQLite is suitable for academic demonstration but should be replaced by PostgreSQL or MySQL for high-volume production deployment.
- Advanced SIEM correlation rules and external log ingestion are future extensions.

## Future Enhancements
- Add real-time log streaming from external systems.
- Integrate email/SMS alert notifications.
- Add MFA for administrator accounts.
- Add visual charts for login trends and alert severity.
- Use real-world anonymized authentication datasets.
- Deploy with a production WSGI server and PostgreSQL.
- Add IP reputation lookup and geolocation enrichment.
- Add REST API endpoints for external security tools.

## Conclusion
The project successfully demonstrates a secure AI-driven SIEM application for authentication analytics. By combining Flask, SQLite, role-based security controls, structured telemetry, audit logs, security alerts, and a Random Forest IDS model, the system provides both practical cybersecurity functionality and strong academic value. The project is suitable for B.Tech submission because it integrates web development, database management, machine learning, and security engineering into a single working application.
