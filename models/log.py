from datetime import datetime, timezone

from app import db


class LoginLog(db.Model):
    __tablename__ = "login_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    ip_address = db.Column(db.String(64), nullable=False)
    user_agent = db.Column(db.String(512), nullable=False, default="")
    country_code = db.Column(db.String(8), nullable=False, default="UNK")
    success = db.Column(db.Boolean, nullable=False, default=False)
    risk_score = db.Column(db.Float, nullable=False, default=0.0)
    suspicious_indicators = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", lazy="joined")


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    action = db.Column(db.String(128), nullable=False)
    target_type = db.Column(db.String(64), nullable=False)
    target_id = db.Column(db.String(64), nullable=False)
    details = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    actor = db.relationship("User", lazy="joined")
