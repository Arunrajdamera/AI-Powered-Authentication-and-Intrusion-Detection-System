from datetime import datetime, timedelta, timezone

from flask import current_app

from app import db
from models.alert import SecurityAlert
from models.log import AuditLog
from models.user import User


class SecurityService:
    @staticmethod
    def register_failed_login(user: User | None, email: str, risk_score: float, login_log_id: int | None) -> SecurityAlert | None:
        threshold = current_app.config["FAILED_LOGIN_THRESHOLD"]
        if user is None:
            return SecurityService.create_alert(
                user_id=None,
                login_log_id=login_log_id,
                incident_class="UNKNOWN_ACCOUNT_LOGIN",
                severity="medium" if risk_score >= current_app.config["MEDIUM_RISK_ALERT_THRESHOLD"] else "low",
                description=f"Failed authentication attempt for non-existent account {email}.",
            )

        user.failed_login_count += 1
        user.last_failed_login_at = datetime.now(timezone.utc).replace(tzinfo=None)
        alert = None
        if user.failed_login_count >= threshold:
            lock_minutes = current_app.config["ACCOUNT_LOCKOUT_MINUTES"]
            user.is_locked = True
            user.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=lock_minutes)
            alert = SecurityService.create_alert(
                user_id=user.id,
                login_log_id=login_log_id,
                incident_class="BRUTE_FORCE_THRESHOLD",
                severity="high",
                description=(
                    f"Account {user.email} locked after {user.failed_login_count} failed login attempts."
                ),
            )
        elif risk_score >= current_app.config["HIGH_RISK_ALERT_THRESHOLD"]:
            alert = SecurityService.create_alert(
                user_id=user.id,
                login_log_id=login_log_id,
                incident_class="HIGH_RISK_AUTHENTICATION",
                severity="high",
                description=f"High-risk failed authentication for {user.email}.",
            )
        return alert

    @staticmethod
    def register_successful_login(user: User) -> None:
        user.failed_login_count = 0
        user.last_failed_login_at = None
        user.is_locked = False
        user.locked_until = None
        user.last_login_at = datetime.now(timezone.utc).replace(tzinfo=None)

    @staticmethod
    def unlock_if_expired(user: User) -> bool:
        if user.is_locked and user.locked_until and user.locked_until <= datetime.now(timezone.utc).replace(tzinfo=None):
            user.is_locked = False
            user.locked_until = None
            user.failed_login_count = 0
            return True
        return False

    @staticmethod
    def create_alert(
        user_id: int | None,
        login_log_id: int | None,
        incident_class: str,
        severity: str,
        description: str,
    ) -> SecurityAlert:
        alert = SecurityAlert(
            user_id=user_id,
            login_log_id=login_log_id,
            incident_class=incident_class,
            severity=severity,
            description=description,
        )
        db.session.add(alert)
        return alert

    @staticmethod
    def audit(actor_user_id: int | None, action: str, target_type: str, target_id: str, details: str = "") -> AuditLog:
        entry = AuditLog(
            actor_user_id=actor_user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details,
        )
        db.session.add(entry)
        return entry
