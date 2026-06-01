from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app import db


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False, default="")
    users = db.relationship("User", back_populates="role", lazy="select")


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_login_at = db.Column(db.DateTime, nullable=True)
    is_active_flag = db.Column(db.Boolean, nullable=False, default=True)
    is_locked = db.Column(db.Boolean, nullable=False, default=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    last_failed_login_at = db.Column(db.DateTime, nullable=True)

    role = db.relationship("Role", back_populates="users")

    @property
    def is_active(self) -> bool:
        return bool(self.is_active_flag) and not self.is_temporarily_locked()

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    def get_id(self) -> str:
        return str(self.id)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        return self.role is not None and self.role.name == "admin"

    def is_temporarily_locked(self) -> bool:
        if not self.is_locked:
            return False
        if self.locked_until is None:
            return True
        return self.locked_until > datetime.now(timezone.utc).replace(tzinfo=None)
