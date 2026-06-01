# Release Notes

## Version 1.0.0

### Release Summary

This release delivers a complete AI-driven SIEM application for authentication analytics. The system includes secure Flask authentication, role-based admin access, login telemetry, audit logs, security alerts, account lockout, CSV exports, and Random Forest based IDS prediction.

### Highlights

- Complete working Flask SIEM application.
- Secure authentication with password hashing and CSRF protection.
- Admin dashboard with user list, alert monitoring, and export links.
- IDS prediction workflow for `Normal` and `Attack` classifications.
- Random Forest model trained and validated on synthetic authentication telemetry.
- Automated test suite with 8 passing tests.
- Academic documentation pack included.

### Model Metrics

| Metric | Value |
|---|---:|
| Accuracy | 88.80% |
| Precision | 66.06% |
| Recall | 88.62% |
| F1 Score | 75.69% |

### Known Limitations

- The IDS model uses synthetic training data.
- SQLite is intended for local and academic demonstration.
- UI is intentionally simple and can be enhanced with Bootstrap or a frontend framework.

### Recommended Release Assets

- Source code ZIP.
- Project report PDF.
- PPT deck.
- Screenshot folder.
- Demo video, if required by the institution.
