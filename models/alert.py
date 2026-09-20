from datetime import datetime, timezone

from extensions import db


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


class SecurityEvent(db.Model):
    """Analyst-facing outcome of applying ML and deterministic rules to a login."""

    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    login_log_id = db.Column(db.Integer, db.ForeignKey("login_logs.id"), nullable=False, unique=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    event_type = db.Column(db.String(64), nullable=False, default="AUTHENTICATION")
    authentication_result = db.Column(db.String(16), nullable=False)
    ml_risk_score = db.Column(db.Float, nullable=False)
    ml_classification = db.Column(db.String(32), nullable=False)
    derived_risk_score = db.Column(db.Float, nullable=False)
    severity = db.Column(db.String(16), nullable=False, index=True)
    indicators = db.Column(db.Text, nullable=False, default="")
    investigation_status = db.Column(db.String(16), nullable=False, default="open", index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    login_log = db.relationship("LoginLog", lazy="joined")
    user = db.relationship("User", lazy="joined")

