import unittest
from unittest.mock import patch
import smtplib

from sqlalchemy import inspect

from app import create_app, db
from config import TestingConfig
from models.alert import SecurityAlert, SecurityEvent
from models.log import AuditLog, LoginLog, PasswordResetToken
from models.user import Role, User


class SiemAppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestingConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        analyst = Role(name="analyst", description="Analyst")
        admin = Role(name="admin", description="Admin")
        db.session.add_all([analyst, admin])
        user = User(email="analyst@example.com", role=analyst)
        user.set_password("StrongPass123!")
        admin_user = User(email="admin@example.com", role=admin)
        admin_user.set_password("AdminPass123!")
        db.session.add_all([user, admin_user])
        db.session.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_database_layer_creates_user_with_role(self):
        user = User.query.filter_by(email="analyst@example.com").first()
        self.assertIsNotNone(user)
        self.assertEqual(user.role.name, "analyst")
        self.assertTrue(user.check_password("StrongPass123!"))
        self.assertNotEqual(user.password_hash, "StrongPass123!")

    def test_required_database_tables_exist(self):
        tables = set(inspect(db.engine).get_table_names())
        self.assertIn("users", tables)
        self.assertIn("login_logs", tables)
        self.assertIn("security_alerts", tables)
        self.assertIn("security_events", tables)
        self.assertIn("password_reset_tokens", tables)

    def test_registration_flow_rejects_weak_password(self):
        response = self.client.post(
            "/register",
            data={"email": "new@example.com", "password": "weak"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(User.query.filter_by(email="new@example.com").first())

    def test_successful_login_records_telemetry(self):
        response = self.client.post(
            "/login",
            data={"email": "analyst@example.com", "password": "StrongPass123!"},
            headers={"X-Known-Device": "1", "X-Country-Code": "US", "X-Expected-Country": "US"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        log = LoginLog.query.filter_by(email="analyst@example.com").first()
        self.assertIsNotNone(log)
        self.assertTrue(log.success)
        event = SecurityEvent.query.filter_by(login_log_id=log.id).first()
        self.assertIsNotNone(event)
        self.assertIn(event.severity, {"normal", "low", "medium", "high", "critical"})

    def test_authentication_lockout_after_threshold(self):
        for _ in range(self.app.config["FAILED_LOGIN_THRESHOLD"]):
            self.client.post(
                "/login",
                data={"email": "analyst@example.com", "password": "WrongPass123!"},
                headers={"X-Forwarded-For": "10.0.0.5"},
            )
        user = User.query.filter_by(email="analyst@example.com").first()
        self.assertTrue(user.is_locked)
        self.assertIsNotNone(user.locked_until)
        self.assertGreaterEqual(SecurityAlert.query.filter_by(incident_class="BRUTE_FORCE_THRESHOLD").count(), 1)

    def test_admin_can_export_alert_csv(self):
        self.client.post(
            "/login",
            data={"email": "admin@example.com", "password": "AdminPass123!"},
            headers={"X-Known-Device": "1"},
        )
        response = self.client.get("/admin/exports/alerts.csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers["Content-Type"])

    def test_admin_dashboard_shows_user_list(self):
        self.client.post(
            "/login",
            data={"email": "admin@example.com", "password": "AdminPass123!"},
            headers={"X-Known-Device": "1"},
        )
        response = self.client.get("/admin/")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("User Monitoring", body)
        self.assertIn("analyst@example.com", body)

    def test_threat_analysis_uses_automatic_telemetry(self):
        self.client.post(
            "/login",
            data={"email": "analyst@example.com", "password": "StrongPass123!"},
            headers={"X-Known-Device": "1"},
        )
        page = self.client.get("/ids/predict")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Latest Authentication Event", page.get_data(as_text=True))
        simulated = self.client.post("/ids/simulate", data={"profile": "failed_burst"})
        self.assertEqual(simulated.status_code, 302)
        self.assertGreaterEqual(SecurityEvent.query.count(), 2)

    def test_password_reset_tokens_are_single_use_and_expire(self):
        from routes.auth import _generate_reset_token
        user = User.query.filter_by(email="analyst@example.com").first()
        with self.app.test_request_context():
            token = _generate_reset_token(user)
            db.session.commit()
        record = PasswordResetToken.query.filter_by(user_id=user.id).first()
        self.assertNotIn(token, record.token_hash)
        response = self.client.post(f"/reset-password/{token}", data={
            "password": "NewStrongPass123!", "confirm_password": "NewStrongPass123!"
        })
        self.assertEqual(response.status_code, 302)
        self.assertIsNotNone(record.used_at)
        self.assertGreaterEqual(AuditLog.query.filter_by(action="PASSWORD_RESET").count(), 1)
        reused = self.client.get(f"/reset-password/{token}")
        self.assertEqual(reused.status_code, 302)
        with self.app.test_request_context():
            expired = _generate_reset_token(user)
            db.session.commit()
        expired_record = PasswordResetToken.query.filter_by(token_hash=__import__("hashlib").sha256(expired.encode()).hexdigest()).first()
        from datetime import datetime, timedelta, timezone
        expired_record.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
        db.session.commit()
        self.assertEqual(self.client.get(f"/reset-password/{expired}").status_code, 302)

    def test_password_reset_request_does_not_disclose_account(self):
        self.app.config.update(
            MAIL_SERVER="smtp.gmail.com", MAIL_PORT=587,
            MAIL_USERNAME="mailer@example.com", MAIL_PASSWORD="test-app-password",
            MAIL_USE_TLS=True, MAIL_DEFAULT_SENDER="", APP_BASE_URL="http://127.0.0.1:5000",
        )
        with patch("routes.auth.smtplib.SMTP") as smtp:
            known = self.client.post("/forgot-password", data={"email": "analyst@example.com"})
            unknown = self.client.post("/forgot-password", data={"email": "nobody@example.com"})
        self.assertIn("If an account exists", known.get_data(as_text=True))
        self.assertIn("If an account exists", unknown.get_data(as_text=True))
        self.assertNotIn("reset-password/", known.get_data(as_text=True))
        self.assertEqual(smtp.call_count, 1)

    def test_gmail_smtp_delivery_uses_tls_and_username_sender_default(self):
        from routes.auth import EMAIL_SENT, _send_password_reset_email
        self.app.config.update(
            MAIL_SERVER="smtp.gmail.com", MAIL_PORT=587,
            MAIL_USERNAME="mailer@example.com", MAIL_PASSWORD="app-password",
            MAIL_USE_TLS=True, MAIL_DEFAULT_SENDER="", APP_BASE_URL="http://127.0.0.1:5000",
        )
        user = User.query.filter_by(email="analyst@example.com").first()
        with patch("routes.auth.smtplib.SMTP") as smtp:
            server = smtp.return_value.__enter__.return_value
            sent = _send_password_reset_email(user, "http://127.0.0.1:5000/reset-password/test-token")
        self.assertEqual(sent, EMAIL_SENT)
        smtp.assert_called_once_with("smtp.gmail.com", 587, timeout=10)
        server.starttls.assert_called_once()
        server.login.assert_called_once_with("mailer@example.com", "app-password")
        message = server.send_message.call_args.args[0]
        self.assertEqual(message["From"], "mailer@example.com")
        self.assertEqual(message["To"], "analyst@example.com")
        self.assertIn("http://127.0.0.1:5000/reset-password/test-token", message.get_content())

    def test_smtp_failure_is_generic_and_does_not_leak_reset_url(self):
        self.app.config.update(
            MAIL_SERVER="smtp.gmail.com", MAIL_PORT=587,
            MAIL_USERNAME="mailer@example.com", MAIL_PASSWORD="app-password",
            MAIL_USE_TLS=True, MAIL_DEFAULT_SENDER="", APP_BASE_URL="http://127.0.0.1:5000",
        )
        with patch("routes.auth.smtplib.SMTP", side_effect=smtplib.SMTPConnectError(421, "unavailable")):
            response = self.client.post("/forgot-password", data={"email": "analyst@example.com"})
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("If an account exists", body)
        self.assertNotIn("reset-password/", body)

    def test_smtp_connection_auth_recipient_and_configuration_states(self):
        from routes.auth import (
            MAIL_CONFIGURATION_MISSING, SMTP_AUTH_FAILED,
            SMTP_CONNECTION_FAILED, SMTP_RECIPIENT_REJECTED,
            _send_password_reset_email,
        )
        user = User.query.filter_by(email="analyst@example.com").first()
        self.app.config.update(
            MAIL_SERVER="smtp.gmail.com", MAIL_PORT=587,
            MAIL_USERNAME="mailer@example.com", MAIL_PASSWORD="app-password",
            MAIL_USE_TLS=True, MAIL_DEFAULT_SENDER="",
        )
        with patch("routes.auth.smtplib.SMTP", side_effect=OSError("network unavailable")):
            self.assertEqual(
                _send_password_reset_email(user, "http://example.test/reset-password/token"),
                SMTP_CONNECTION_FAILED,
            )
        with patch("routes.auth.smtplib.SMTP") as smtp:
            smtp.return_value.__enter__.return_value.login.side_effect = smtplib.SMTPAuthenticationError(535, b"denied")
            self.assertEqual(
                _send_password_reset_email(user, "http://example.test/reset-password/token"),
                SMTP_AUTH_FAILED,
            )
        with patch("routes.auth.smtplib.SMTP") as smtp:
            smtp.return_value.__enter__.return_value.send_message.side_effect = smtplib.SMTPRecipientsRefused({"analyst@example.com": (550, b"rejected")})
            self.assertEqual(
                _send_password_reset_email(user, "http://example.test/reset-password/token"),
                SMTP_RECIPIENT_REJECTED,
            )
        self.app.config["MAIL_PASSWORD"] = ""
        self.assertEqual(
            _send_password_reset_email(user, "http://example.test/reset-password/token"),
            MAIL_CONFIGURATION_MISSING,
        )

    def test_reset_url_requires_valid_public_base_url(self):
        from routes.auth import _build_reset_url
        self.app.config["APP_BASE_URL"] = "http://127.0.0.1:5000"
        with self.app.test_request_context():
            self.assertEqual(
                _build_reset_url("safe-token"),
                "http://127.0.0.1:5000/reset-password/safe-token",
            )
        self.app.config["APP_BASE_URL"] = "not-a-url"
        with self.app.test_request_context():
            self.assertIsNone(_build_reset_url("safe-token"))


if __name__ == "__main__":
    unittest.main()
