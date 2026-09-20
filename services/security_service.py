from datetime import datetime, timedelta, timezone

from flask import current_app

from extensions import db
from models.alert import SecurityAlert, SecurityEvent
from models.log import AuditLog
from models.user import User


class SecurityService:
    @staticmethod
    def analyze_authentication(
        *,
        login_log_id: int,
        user_id: int | None,
        success: bool,
        ml_risk_score: float,
        indicators: list[str],
    ) -> SecurityEvent:
        """Persist the explainable correlation layer around the IDS model result.

        The ML score remains distinct from deterministic indicator weighting and
        the analyst-facing severity assigned below.
        """
        normalized_ml_score = max(0.0, min(float(ml_risk_score), 1.0))
        rule_bonus = min(0.30, 0.04 * len(indicators))
        if not success:
            rule_bonus += 0.08
        derived_score = min(1.0, normalized_ml_score + rule_bonus)
        if derived_score >= 0.85:
            severity = "critical"
        elif derived_score >= 0.65:
            severity = "high"
        elif derived_score >= 0.40:
            severity = "medium"
        elif derived_score >= 0.20:
            severity = "low"
        else:
            severity = "normal"
        ml_classification = "SUSPICIOUS" if normalized_ml_score >= 0.50 else "NORMAL"
        event = SecurityEvent(
            login_log_id=login_log_id,
            user_id=user_id,
            authentication_result="SUCCESS" if success else "FAILED",
            ml_risk_score=normalized_ml_score,
            ml_classification=ml_classification,
            derived_risk_score=derived_score,
            severity=severity,
            indicators=";".join(indicators) or "none",
        )
        db.session.add(event)
        db.session.flush()
        if severity in {"medium", "high", "critical"}:
            SecurityService.create_alert(
                user_id=user_id,
                login_log_id=login_log_id,
                incident_class="AUTHENTICATION_RISK",
                severity=severity,
                description=(
                    f"{event.authentication_result} authentication correlated as {severity.upper()}. "
                    f"ML classification={ml_classification}; ML score={normalized_ml_score:.3f}; "
                    f"derived score={derived_score:.3f}; indicators={event.indicators}."
                ),
            )
        return event
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

