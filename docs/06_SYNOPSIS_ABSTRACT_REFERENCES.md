# Project Synopsis

## Title
AI-Driven Security Information and Event Management System with Random Forest Based Intrusion Detection for Authentication Analytics

## Synopsis
The project is a secure web-based SIEM application developed using Python Flask. It focuses on authentication analytics by monitoring user login activity, recording telemetry, detecting suspicious behavior, and assisting administrators in incident review. The system supports user registration, login, logout, role-based access, admin dashboard, login history, audit logs, security alerts, CSV exports, and session management.

A machine learning based IDS module is integrated using the Random Forest algorithm. The model is trained on synthetic authentication data containing features such as login hour, previous failed attempts, suspicious IP flag, country mismatch flag, and new device flag. The prediction page classifies activity as Normal or Attack. The system achieved 88.80% accuracy, 66.06% precision, 88.62% recall, and 75.69% F1 score.

The project demonstrates secure software development practices, database-backed web design, machine learning integration, and cybersecurity monitoring. It is suitable for academic demonstration and can be extended into a production-grade SIEM platform with real log sources, notification systems, and enterprise database support.

## Abstract
Authentication attacks are a major concern for modern web applications. Conventional login systems usually verify credentials but do not provide sufficient monitoring, risk analysis, or incident response support. This project proposes and implements an AI-driven SIEM application for authentication analytics using Python Flask, SQLite, and a Random Forest based IDS model.

The system records login telemetry, maintains audit logs, detects repeated failed attempts, locks accounts after threshold violations, generates security alerts, and provides an admin dashboard for monitoring and resolution. A machine learning module classifies authentication samples into Normal and Attack classes. The trained Random Forest model achieved 88.80% accuracy and 88.62% recall, showing effective detection capability for suspicious authentication behavior. The project integrates secure authentication, web application development, database design, and machine learning into a complete cybersecurity monitoring solution.

## IEEE-Style References

[1] Pallets Projects, "Flask Documentation." Accessed: Jun. 2, 2026. [Online]. Available: https://flask.palletsprojects.com/

[2] Pallets Projects, "Werkzeug Security Helpers." Accessed: Jun. 2, 2026. [Online]. Available: https://werkzeug.palletsprojects.com/

[3] SQLAlchemy, "SQLAlchemy Documentation." Accessed: Jun. 2, 2026. [Online]. Available: https://docs.sqlalchemy.org/

[4] Flask-Login, "Flask-Login Documentation." Accessed: Jun. 2, 2026. [Online]. Available: https://flask-login.readthedocs.io/

[5] Flask-WTF, "Flask-WTF Documentation." Accessed: Jun. 2, 2026. [Online]. Available: https://flask-wtf.readthedocs.io/

[6] scikit-learn Developers, "RandomForestClassifier." Accessed: Jun. 2, 2026. [Online]. Available: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html

[7] scikit-learn Developers, "Model Evaluation: Quantifying the Quality of Predictions." Accessed: Jun. 2, 2026. [Online]. Available: https://scikit-learn.org/stable/modules/model_evaluation.html

[8] SQLite Consortium, "SQLite Documentation." Accessed: Jun. 2, 2026. [Online]. Available: https://www.sqlite.org/docs.html

[9] OWASP Foundation, "Authentication Cheat Sheet." Accessed: Jun. 2, 2026. [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

[10] OWASP Foundation, "Cross-Site Request Forgery Prevention Cheat Sheet." Accessed: Jun. 2, 2026. [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

[11] OWASP Foundation, "Session Management Cheat Sheet." Accessed: Jun. 2, 2026. [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

[12] National Institute of Standards and Technology, "Digital Identity Guidelines: Authentication and Authenticator Management, NIST SP 800-63B." Accessed: Jun. 2, 2026. [Online]. Available: https://pages.nist.gov/800-63-3/sp800-63b.html

[13] L. Breiman, "Random Forests," Machine Learning, vol. 45, no. 1, pp. 5-32, 2001.

[14] F. Pedregosa et al., "Scikit-learn: Machine Learning in Python," Journal of Machine Learning Research, vol. 12, pp. 2825-2830, 2011.

[15] Python Software Foundation, "Python Documentation." Accessed: Jun. 2, 2026. [Online]. Available: https://docs.python.org/
