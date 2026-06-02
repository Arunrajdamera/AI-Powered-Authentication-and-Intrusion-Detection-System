from flask import Blueprint, current_app, redirect, render_template_string, request, url_for
from flask_login import current_user, login_required

from ml.predict import IntrusionPredictor
from models.alert import SecurityAlert
from models.log import LoginLog


main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    if current_user.is_admin():
        return redirect(url_for("admin.portal"))
    logs = LoginLog.query.filter_by(user_id=current_user.id).order_by(LoginLog.created_at.desc()).limit(25).all()
    alerts = SecurityAlert.query.filter_by(user_id=current_user.id).order_by(SecurityAlert.created_at.desc()).limit(10).all()
    return render_template_string(
        """
        <h1>Personal Telemetry</h1>
        <p>{{ current_user.email }}</p>
        <form method="post" action="{{ url_for('auth.logout') }}">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <button type="submit">Logout</button>
        </form>
        <p><a href="{{ url_for('main.predict_ids') }}">IDS Prediction</a></p>
        <h2>Recent Login Events</h2>
        <ul>{% for log in logs %}<li>{{ log.created_at }} | success={{ log.success }} | risk={{ "%.2f"|format(log.risk_score) }}</li>{% endfor %}</ul>
        <h2>Alerts</h2>
        <ul>{% for alert in alerts %}<li>{{ alert.severity }} | {{ alert.incident_class }} | resolved={{ alert.is_resolved }}</li>{% endfor %}</ul>
        """,
        logs=logs,
        alerts=alerts,
    )


@main_bp.route("/ids/predict", methods=["GET", "POST"])
@login_required
def predict_ids():
    result = None
    risk_score = None
    if request.method == "POST":
        features = [
            float(request.form.get("login_hour", "12")),
            float(request.form.get("preceding_fails", "0")),
            float(1 if request.form.get("suspicious_ip") == "on" else 0),
            float(1 if request.form.get("country_mismatch") == "on" else 0),
            float(1 if request.form.get("new_device") == "on" else 0),
        ]
        predictor = IntrusionPredictor(current_app.config["MODEL_PATH"])
        risk_score = predictor.predict_risk(features)
        result = "Attack" if risk_score >= 0.5 else "Normal"

    return render_template_string(
        """
<!DOCTYPE html>

<html>
<head>

<title>IDS Threat Analysis</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

<style>
body{
    background:#f4f7fc;
}

.card-custom{
    border:none;
    border-radius:15px;
    box-shadow:0 4px 15px rgba(0,0,0,.08);
}
</style>

</head>

<body>

<div class="container mt-4">

<h2 class="mb-4">
🛡 IDS Threat Analysis Dashboard
</h2>

<a href="{{ url_for('main.dashboard') }}"
class="btn btn-secondary mb-4">
Dashboard </a>

<div class="card card-custom p-4 mb-4">

<form method="post">

<input type="hidden"
    name="csrf_token"
    value="{{ csrf_token() }}">

<div class="row">

<div class="col-md-6 mb-3">
<label class="form-label">Login Hour</label>
<input class="form-control"
       name="login_hour"
       type="number"
       min="0"
       max="23"
       value="12"
       required>
</div>

<div class="col-md-6 mb-3">
<label class="form-label">Previous Failed Attempts</label>
<input class="form-control"
       name="preceding_fails"
       type="number"
       min="0"
       max="20"
       value="0"
       required>
</div>

</div>

<div class="form-check">
<input class="form-check-input"
       name="suspicious_ip"
       type="checkbox">
<label class="form-check-label">
Suspicious IP
</label>
</div>

<div class="form-check">
<input class="form-check-input"
       name="country_mismatch"
       type="checkbox">
<label class="form-check-label">
Country Mismatch
</label>
</div>

<div class="form-check mb-3">
<input class="form-check-input"
       name="new_device"
       type="checkbox">
<label class="form-check-label">
New Device
</label>
</div>

<button class="btn btn-primary">
Analyze Threat
</button>

</form>

</div>

{% if result %}

<div class="card card-custom p-4">

<h3>Threat Analysis Result</h3>

{% if result == "Attack" %}

<div class="alert alert-danger border border-danger">
<h4 class="fw-bold text-danger">
🚨 HIGH RISK INTRUSION DETECTED
</h4>
<p>Risk Score:
<strong>{{ "%.3f"|format(risk_score) }}</strong></p>
<p>
Threat Level:

{% if risk_score >= 0.8 %}
<span class="badge bg-danger">Critical</span>

{% elif risk_score >= 0.5 %}
<span class="badge bg-warning text-dark">Medium Risk</span>

{% else %}
<span class="badge bg-success">Low Risk</span>

{% endif %}
</p>
</div>

{% else %}

<div class="alert alert-success border border-success">
<h4>✅ NORMAL ACTIVITY</h4>
<p>Risk Score:
<strong>{{ "%.3f"|format(risk_score) }}</strong></p>
<p>
Threat Level:

{% if risk_score >= 0.8 %}
<span class="badge bg-danger">Critical</span>

{% elif risk_score >= 0.5 %}
<span class="badge bg-warning text-dark">Medium Risk</span>

{% else %}
<span class="badge bg-success">Low Risk</span>

{% endif %}
</p>
</div>

{% endif %}

</div>

{% endif %}

</div>

</body>
</html>

                """,
        result=result,
        risk_score=risk_score,
    )
