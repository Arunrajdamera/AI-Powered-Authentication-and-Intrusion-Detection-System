# 30 Viva Questions and Answers

1. What is the main objective of your project?  
The objective is to build a secure SIEM-style web application that monitors authentication events, detects suspicious login behavior, generates security alerts, and uses a Random Forest model for IDS classification.

2. Why did you choose Flask?  
Flask is lightweight, flexible, and suitable for building modular Python web applications. It allows easy integration with authentication, databases, and machine learning components.

3. What is SIEM?  
SIEM stands for Security Information and Event Management. It collects, stores, analyzes, and reports security-related events to help detect incidents.

4. What authentication features are implemented?  
The system supports registration, login, logout, password hashing, CSRF protection, session management, failed login tracking, and account lockout.

5. How are passwords stored?  
Passwords are stored as secure hashes using Werkzeug password hashing functions. Plain-text passwords are never stored.

6. What is CSRF protection?  
CSRF protection prevents unauthorized form submissions from another website by requiring a valid token in every POST request.

7. Why is account lockout used?  
Account lockout reduces brute-force risk by temporarily locking an account after repeated failed login attempts.

8. What database is used?  
SQLite is used because it is lightweight, file-based, easy to configure, and suitable for academic project deployment.

9. Which tables are present in the database?  
The main tables are users, roles, login_logs, audit_logs, and security_alerts.

10. What is stored in login_logs?  
It stores email, user ID, IP address, user agent, country code, success status, risk score, suspicious indicators, and timestamp.

11. What is the purpose of audit_logs?  
Audit logs preserve security-sensitive actions such as login success, logout, registration, admin seeding, and alert resolution.

12. What is a security alert?  
A security alert is an incident record generated when suspicious activity occurs, such as brute-force threshold violation or high-risk authentication.

13. What machine learning algorithm is used?  
The system uses a Random Forest classifier.

14. Why Random Forest?  
Random Forest is robust, handles nonlinear feature relationships, reduces overfitting through multiple decision trees, and performs well on structured tabular data.

15. What are the IDS input features?  
The features are login hour, previous failed attempts, suspicious IP flag, country mismatch flag, and new device flag.

16. What are the IDS output classes?  
The output classes are Normal and Attack.

17. What accuracy did the model achieve?  
The model achieved 88.80% accuracy.

18. What does recall mean in this project?  
Recall measures how many actual attacks were correctly detected. High recall is important because missed attacks can be dangerous.

19. What was the model recall?  
The model achieved 88.62% recall.

20. What is precision?  
Precision measures how many predicted attacks were actually attacks. It helps estimate false positive behavior.

21. What was the model precision?  
The model achieved 66.06% precision.

22. What is F1 score?  
F1 score is the harmonic mean of precision and recall. It balances false positives and false negatives.

23. How does the admin dashboard help?  
It shows users, login events, open alerts, audit logs, user list, alert controls, IDS prediction access, and CSV export links.

24. How are CSV exports useful?  
CSV exports allow administrators to download SIEM records for offline analysis, reporting, or evidence documentation.

25. How is admin access protected?  
Admin pages require authentication and check that the logged-in user has the admin role.

26. What happens when a wrong password is entered?  
The failed attempt is logged, failed count is increased, risk is calculated, and alerts or lockout may be triggered after thresholds are reached.

27. What is session management?  
Session management maintains logged-in user identity across requests and expires sessions after a configured lifetime.

28. What testing was performed?  
Automated tests verify database creation, password hashing, login telemetry, account lockout, admin exports, user list visibility, and IDS prediction classes.

29. What are the limitations of the project?  
The IDS model uses synthetic data, the UI is simple, and SQLite is not intended for high-volume enterprise deployment.

30. What future enhancements can be added?  
Future work includes MFA, real datasets, PostgreSQL, visual charts, email alerts, IP reputation lookup, and deployment using a production WSGI server.
