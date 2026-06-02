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
        <!DOCTYPE html>
<html>
<head>

<title>Security Dashboard</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

<style>

body{
    background:#f5f7fb;
}

.stat-card{
    border:none;
    border-radius:15px;
    box-shadow:0 4px 15px rgba(0,0,0,.08);
}

</style>

</head>

<body>

<div class="container mt-4">

<h2 class="mb-4">
🛡 Security Administration Dashboard
</h2>

<div class="row mb-4">

<div class="col-md-3">
<div class="card stat-card p-3">
<h6>Total Users</h6>
<h3>{{ totals.users }}</h3>
</div>
</div>

<div class="col-md-3">
<div class="card stat-card p-3">
<h6>Login Events</h6>
<h3>{{ totals.login_logs }}</h3>
</div>
</div>

<div class="col-md-3">
<div class="card stat-card p-3">
<h6>Open Alerts</h6>
<h3>{{ totals.open_alerts }}</h3>
</div>
</div>

<div class="col-md-3">
<div class="card stat-card p-3">
<h6>Audit Logs</h6>
<h3>{{ totals.audit_logs }}</h3>
</div>
</div>

</div>

<div class="mb-4">

<a href="{{ url_for('main.predict_ids') }}"
   class="btn btn-primary me-2">
   IDS Prediction
</a>

<a href="{{ url_for('admin.export_login_logs') }}"
   class="btn btn-success me-2">
   Export Login Logs
</a>

<a href="{{ url_for('admin.export_alerts') }}"
   class="btn btn-warning me-3">
   Export Alerts
</a>

<form method="post"
      action="{{ url_for('auth.logout') }}"
      class="d-inline">

<input type="hidden"
       name="csrf_token"
       value="{{ csrf_token() }}">

<button class="btn btn-danger">
Logout
</button>

</form>

</div>

<div class="card p-3 mb-4">

<h4>User List</h4>
<p class="text-muted">User Management</p>

<table class="table table-striped">

<thead>
<tr>
<th>ID</th>
<th>Email</th>
<th>Role</th>
<th>Status</th>
<th>Failed Logins</th>
</tr>
</thead>

<tbody>

{% for user in users %}
<tr>
<td>{{ user.id }}</td>
<td>{{ user.email }}</td>
<td>{{ user.role.name }}</td>

<td>
{% if user.is_locked %}
<span class="badge bg-danger">
Locked
</span>
{% else %}
<span class="badge bg-success">
Active
</span>
{% endif %}
</td>

<td>{{ user.failed_login_count }}</td></tr>
{% endfor %}

</tbody>

</table>

</div>

<div class="card p-3">

<h4>Security Alerts</h4>

<table class="table">

<thead>
<tr>
<th>ID</th>
<th>Severity</th>
<th>Incident</th>
</tr>
</thead>

<tbody>

{% for alert in alerts %}
<tr>
<td>{{ alert.id }}</td>
<td>

{% if alert.severity == 'high' %}
<span class="badge bg-danger">
High
</span>

{% elif alert.severity == 'medium' %}
<span class="badge bg-warning text-dark">
Medium
</span>

{% else %}
<span class="badge bg-success">
Low
</span>

{% endif %}

</td>
<td>{{ alert.incident_class }}</td>
</tr>
{% endfor %}

</tbody>

</table>

</div>

</div>

</body>
</html>
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
