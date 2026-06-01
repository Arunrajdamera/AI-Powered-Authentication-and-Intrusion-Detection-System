from datetime import datetime, timezone

from flask import Blueprint, Response, abort, redirect, render_template_string, url_for
from flask_login import current_user, login_required

from app import db
from models.alert import SecurityAlert
from models.log import AuditLog, LoginLog
from models.user import User
from services.report_service import ReportService
from services.security_service import SecurityService


admin_bp = Blueprint("admin", __name__)


def _require_admin() -> None:
    if not current_user.is_authenticated or not current_user.is_admin():
        abort(403)


@admin_bp.route("/")
@login_required
def portal():
    _require_admin()
    totals = {
        "users": User.query.count(),
        "login_logs": LoginLog.query.count(),
        "open_alerts": SecurityAlert.query.filter_by(is_resolved=False).count(),
        "audit_logs": AuditLog.query.count(),
    }
    alerts = SecurityAlert.query.order_by(SecurityAlert.created_at.desc()).limit(50).all()
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template_string(
        """
        <h1>Security Administration</h1>
        <p>Users: {{ totals.users }} | Login events: {{ totals.login_logs }} | Open alerts: {{ totals.open_alerts }} | Audit logs: {{ totals.audit_logs }}</p>
        <form method="post" action="{{ url_for('auth.logout') }}">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <button type="submit">Logout</button>
        </form>
        <a href="{{ url_for('admin.export_login_logs') }}">Export Login Logs</a>
        <a href="{{ url_for('admin.export_alerts') }}">Export Alerts</a>
        <a href="{{ url_for('main.predict_ids') }}">IDS Prediction</a>
        <h2>User List</h2>
        <table>
          <thead><tr><th>ID</th><th>Email</th><th>Role</th><th>Active</th><th>Locked</th><th>Failed Logins</th></tr></thead>
          <tbody>
          {% for user in users %}
            <tr>
              <td>{{ user.id }}</td>
              <td>{{ user.email }}</td>
              <td>{{ user.role.name }}</td>
              <td>{{ user.is_active_flag }}</td>
              <td>{{ user.is_locked }}</td>
              <td>{{ user.failed_login_count }}</td>
            </tr>
          {% endfor %}
          </tbody>
        </table>
        <h2>Security Alerts</h2>
        <ul>
        {% for alert in alerts %}
          <li>{{ alert.id }} | {{ alert.severity }} | {{ alert.incident_class }} | resolved={{ alert.is_resolved }}
          <form method="post" action="{{ url_for('admin.toggle_alert', alert_id=alert.id) }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button type="submit">Toggle Resolution</button>
          </form></li>
        {% endfor %}
        </ul>
        """,
        totals=totals,
        alerts=alerts,
        users=users,
    )


@admin_bp.route("/alerts/<int:alert_id>/toggle", methods=["POST"])
@login_required
def toggle_alert(alert_id: int):
    _require_admin()
    alert = db.session.get(SecurityAlert, alert_id)
    if alert is None:
        abort(404)
    alert.is_resolved = not alert.is_resolved
    alert.resolved_by_user_id = current_user.id if alert.is_resolved else None
    alert.resolved_at = datetime.now(timezone.utc).replace(tzinfo=None) if alert.is_resolved else None
    SecurityService.audit(
        current_user.id,
        "TOGGLE_ALERT_RESOLUTION",
        "SecurityAlert",
        str(alert.id),
        f"Resolution state changed to {alert.is_resolved}.",
    )
    db.session.commit()
    return redirect(url_for("admin.portal"))


@admin_bp.route("/exports/login-logs.csv")
@login_required
def export_login_logs():
    _require_admin()
    rows = (
        (
            log.id,
            log.user_id,
            log.email,
            log.ip_address,
            log.success,
            f"{log.risk_score:.4f}",
            log.suspicious_indicators,
            log.created_at,
        )
        for log in LoginLog.query.order_by(LoginLog.created_at.desc()).all()
    )
    csv_data = ReportService.rows_to_csv(
        ["id", "user_id", "email", "ip_address", "success", "risk_score", "suspicious_indicators", "created_at"],
        rows,
    )
    return _csv_response(csv_data, "login-logs.csv")


@admin_bp.route("/exports/alerts.csv")
@login_required
def export_alerts():
    _require_admin()
    rows = (
        (
            alert.id,
            alert.user_id,
            alert.login_log_id,
            alert.incident_class,
            alert.severity,
            alert.description,
            alert.is_resolved,
            alert.created_at,
            alert.resolved_at,
        )
        for alert in SecurityAlert.query.order_by(SecurityAlert.created_at.desc()).all()
    )
    csv_data = ReportService.rows_to_csv(
        ["id", "user_id", "login_log_id", "incident_class", "severity", "description", "is_resolved", "created_at", "resolved_at"],
        rows,
    )
    return _csv_response(csv_data, "alerts.csv")


def _csv_response(csv_data: str, filename: str) -> Response:
    response = Response(csv_data, mimetype="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response
