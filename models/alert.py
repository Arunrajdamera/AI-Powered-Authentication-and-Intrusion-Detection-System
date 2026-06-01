from datetime import datetime, timezone

from app import db


class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    login_log_id = db.Column(db.Integer, db.ForeignKey("login_logs.id"), nullable=True, index=True)
    incident_class = db.Column(db.String(64), nullable=False, index=True)
    severity = db.Column(db.String(16), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    is_resolved = db.Column(db.Boolean, nullable=False, default=False)
    resolved_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", foreign_keys=[user_id], lazy="joined")
    login_log = db.relationship("LoginLog", lazy="joined")
    resolver = db.relationship("User", foreign_keys=[resolved_by_user_id], lazy="joined")
