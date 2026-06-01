# Changelog

All notable changes to this project are documented here.

## [1.0.0] - 2026-06-02

### Added

- Flask authentication system.
- Role-based admin dashboard.
- User registration, login, logout, and session management.
- SQLite database models for users, roles, login logs, audit logs, and security alerts.
- Password hashing and CSRF protection.
- Failed login tracking and account lockout.
- Login telemetry and audit logging.
- Security alert generation and resolution workflow.
- CSV export for login logs and alerts.
- Random Forest IDS dataset generation, training, and prediction.
- IDS prediction page with `Normal` and `Attack` classes.
- Automated unit tests.
- GitHub Actions workflow.
- Academic documentation pack.
- GitHub-ready README, license, contribution guide, release notes, and publish checklist.

### Validation

- 8 automated tests passing.
- Random Forest accuracy: 88.80%.
- Precision: 66.06%.
- Recall: 88.62%.
- F1 score: 75.69%.
