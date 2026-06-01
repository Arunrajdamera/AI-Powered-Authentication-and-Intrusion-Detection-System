import unittest

from sqlalchemy import inspect

from app import create_app, db
from config import TestingConfig
from models.alert import SecurityAlert
from models.log import LoginLog
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
        self.assertIn("User List", body)
        self.assertIn("analyst@example.com", body)

    def test_ids_prediction_page_classifies_normal_and_attack(self):
        self.client.post(
            "/login",
            data={"email": "analyst@example.com", "password": "StrongPass123!"},
            headers={"X-Known-Device": "1"},
        )
        normal = self.client.post(
            "/ids/predict",
            data={"login_hour": "12", "preceding_fails": "0"},
        )
        self.assertEqual(normal.status_code, 200)
        self.assertIn("Normal", normal.get_data(as_text=True))

        attack = self.client.post(
            "/ids/predict",
            data={
                "login_hour": "2",
                "preceding_fails": "8",
                "suspicious_ip": "on",
                "country_mismatch": "on",
                "new_device": "on",
            },
        )
        self.assertEqual(attack.status_code, 200)
        self.assertIn("Attack", attack.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
