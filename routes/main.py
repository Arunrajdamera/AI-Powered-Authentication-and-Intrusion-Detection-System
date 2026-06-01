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
        <h1>IDS Prediction</h1>
        <p><a href="{{ url_for('main.dashboard') }}">Dashboard</a></p>
        <form method="post">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <label>Login Hour <input name="login_hour" type="number" min="0" max="23" value="12" required></label>
          <label>Previous Failed Attempts <input name="preceding_fails" type="number" min="0" max="20" value="0" required></label>
          <label><input name="suspicious_ip" type="checkbox"> Suspicious IP</label>
          <label><input name="country_mismatch" type="checkbox"> Country Mismatch</label>
          <label><input name="new_device" type="checkbox"> New Device</label>
          <button type="submit">Classify</button>
        </form>
        {% if result %}
          <h2>IDS Prediction Result</h2>
          <p>Class: <strong>{{ result }}</strong></p>
          <p>Risk Score: {{ "%.3f"|format(risk_score) }}</p>
        {% endif %}
        """,
        result=result,
        risk_score=risk_score,
    )
