import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app, db
from models.user import Role, User
from services.security_service import SecurityService


def seed_admin() -> None:
    load_dotenv(ROOT / ".env")
    app = create_app()
    with app.app_context():
        db.create_all()
        admin_role = _get_or_create_role("admin", "Security administrator with full SIEM access")
        _get_or_create_role("analyst", "Standard user with personal telemetry access")

        admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
        admin_password = os.getenv("ADMIN_PASSWORD", "AdminPass123!")
        admin = User.query.filter_by(email=admin_email).first()
        if admin is None:
            admin = User(email=admin_email, role=admin_role)
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.flush()
            SecurityService.audit(None, "SEED_ADMIN", "User", str(admin.id), f"Created bootstrap admin {admin_email}.")
        else:
            admin.role = admin_role
            admin.is_active_flag = True
            SecurityService.audit(None, "SEED_ADMIN_REFRESH", "User", str(admin.id), f"Confirmed bootstrap admin {admin_email}.")
        db.session.commit()
        print(f"Admin account ready: {admin_email}")


def _get_or_create_role(name: str, description: str) -> Role:
    role = Role.query.filter_by(name=name).first()
    if role is None:
        role = Role(name=name, description=description)
        db.session.add(role)
        db.session.flush()
    return role


if __name__ == "__main__":
    seed_admin()
