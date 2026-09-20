from datetime import datetime, timezone

from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template_string,
    request, flash,
    url_for,
)
from flask_login import current_user, login_required

from extensions import db
from ml.predict import IntrusionPredictor
from models.alert import SecurityAlert, SecurityEvent
from models.log import AuditLog, LoginLog
from services.security_service import SecurityService


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

    logs = (
        LoginLog.query
        .filter_by(user_id=current_user.id)
        .order_by(LoginLog.created_at.desc())
        .limit(25)
        .all()
    )

    alerts = (
        SecurityAlert.query
        .filter_by(user_id=current_user.id)
        .order_by(SecurityAlert.created_at.desc())
        .limit(10)
        .all()
    )

    return render_template_string(
        """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Personal Telemetry</title>

            <link
                href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
                rel="stylesheet"
            >

            <style>
                body {
                    background: #061014;
                    color: #e6f7ff;
                    font-family: Arial, sans-serif;
                }

                .container {
                    max-width: 1100px;
                }

                .card {
                    background: #0a181d;
                    border: 1px solid #153942;
                    border-radius: 14px;
                    color: #e6f7ff;
                }

                .table {
                    color: #dceff5;
                }

                .table th {
                    color: #55c9e8;
                }

                .table td {
                    border-color: #153942;
                }

                .btn-cyber {
                    border: 1px solid #00d9ff;
                    color: #00d9ff;
                    background: transparent;
                }

                .btn-cyber:hover {
                    background: #00d9ff;
                    color: #001014;
                }

                .text-muted {
                    color: #7195a3 !important;
                }
            </style>
        </head>

        <body>

        <div class="container mt-5">

            <div class="d-flex justify-content-between align-items-center mb-4">
                <div>
                    <div class="text-uppercase"
                         style="color:#00d9ff; letter-spacing:3px;">
                        Security Monitoring
                    </div>

                    <h1 class="mt-2">
                        Personal Telemetry
                    </h1>

                    <p class="text-muted">
                        {{ current_user.email }}
                    </p>
                </div>

                <div>
                    <a
                        href="{{ url_for('main.threat_analysis') }}"
                        class="btn btn-cyber me-2"
                    >
                        IDS ANALYSIS
                    </a>

                    <form
                        method="post"
                        action="{{ url_for('auth.logout') }}"
                        class="d-inline"
                    >
                        <input
                            type="hidden"
                            name="csrf_token"
                            value="{{ csrf_token() }}"
                        >

                        <button class="btn btn-outline-danger">
                            LOGOUT
                        </button>
                    </form>
                </div>
            </div>


            <div class="card p-4 mb-4">

                <h4>Recent Login Events</h4>

                <div class="table-responsive mt-3">

                    <table class="table">

                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Time</th>
                                <th>Result</th>
                                <th>Risk</th>
                                <th>Indicators</th>
                            </tr>
                        </thead>

                        <tbody>

                        {% for log in logs %}

                            <tr>

                                <td>#{{ log.id }}</td>

                                <td>
                                    {{ log.created_at }}
                                </td>

                                <td>

                                    {% if log.success %}

                                        <span
                                            style="
                                                color:#00e676;
                                                font-weight:bold;
                                            "
                                        >
                                            SUCCESS
                                        </span>

                                    {% else %}

                                        <span
                                            style="
                                                color:#ff4d5a;
                                                font-weight:bold;
                                            "
                                        >
                                            FAILED
                                        </span>

                                    {% endif %}

                                </td>

                                <td>
                                    {{ "%.3f"|format(log.risk_score) }}
                                </td>

                                <td>
                                    {{ log.suspicious_indicators }}
                                </td>

                            </tr>

                        {% else %}

                            <tr>
                                <td colspan="5" class="text-muted">
                                    No login telemetry available.
                                </td>
                            </tr>

                        {% endfor %}

                        </tbody>

                    </table>

                </div>

            </div>


            <div class="card p-4">

                <div class="d-flex justify-content-between">

                    <div>
                        <h4>Security Alerts</h4>

                        <p class="text-muted">
                            Alerts associated with your account
                        </p>
                    </div>

                    <span style="color:#00e676;">
                        {{ alerts|length }} EVENTS
                    </span>

                </div>


                <div class="table-responsive">

                    <table class="table">

                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Severity</th>
                                <th>Incident</th>
                                <th>Status</th>
                                <th>Created</th>
                            </tr>
                        </thead>

                        <tbody>

                        {% for alert in alerts %}

                            <tr>

                                <td>#{{ alert.id }}</td>

                                <td>

                                    {% if alert.severity == "high" %}

                                        <span
                                            style="
                                                color:#ff4d5a;
                                                font-weight:bold;
                                            "
                                        >
                                            HIGH
                                        </span>

                                    {% elif alert.severity == "medium" %}

                                        <span
                                            style="
                                                color:#ffd21f;
                                                font-weight:bold;
                                            "
                                        >
                                            MEDIUM
                                        </span>

                                    {% else %}

                                        <span
                                            style="
                                                color:#00e676;
                                                font-weight:bold;
                                            "
                                        >
                                            LOW
                                        </span>

                                    {% endif %}

                                </td>

                                <td>
                                    {{ alert.incident_class }}
                                </td>

                                <td>

                                    {% if alert.is_resolved %}

                                        <span
                                            style="
                                                color:#00e676;
                                                font-weight:bold;
                                            "
                                        >
                                            RESOLVED
                                        </span>

                                    {% else %}

                                        <span
                                            style="
                                                color:#ff4d5a;
                                                font-weight:bold;
                                            "
                                        >
                                            OPEN
                                        </span>

                                    {% endif %}

                                </td>

                                <td>
                                    {{ alert.created_at }}
                                </td>

                            </tr>

                        {% else %}

                            <tr>
                                <td colspan="5" class="text-muted">
                                    No security alerts.
                                </td>
                            </tr>

                        {% endfor %}

                        </tbody>

                    </table>

                </div>

            </div>

        </div>

        </body>
        </html>
        """,
        logs=logs,
        alerts=alerts,
    )


THREAT_ANALYSIS_TEMPLATE = """<!doctype html><title>SOC Threat Analysis</title><style>body{background:#061014;color:#e6f7ff;font:15px Arial;margin:0;padding:32px}.wrap{max-width:1100px;margin:auto}.panel{background:#0a181d;border:1px solid #1d5665;border-radius:12px;padding:22px;margin:18px 0}.sev{font-weight:bold}.critical{color:#ff5270}.high{color:#ff8452}.medium{color:#ffd45b}.low{color:#56cbe5}.normal{color:#45e093}table{width:100%;border-collapse:collapse}td,th{padding:10px;border-bottom:1px solid #18363e;text-align:left}button,a{background:#09323e;color:#7be9ff;border:1px solid #21b7d1;padding:10px;text-decoration:none;border-radius:5px}.muted{color:#83aeb9}</style><main class=wrap><a href="{{ url_for('main.dashboard') }}">Dashboard</a><h1>Threat Analysis</h1><p class=muted>Authentication telemetry is collected and assessed automatically. ML output, deterministic indicators, derived risk, and alert severity are separate.</p>{% with messages=get_flashed_messages() %}{% for m in messages %}<div class=panel>{{m}}</div>{% endfor %}{% endwith %}{% if latest %}<section class=panel><h2>Latest Authentication Event #{{latest.id}}</h2><p><b>{{latest.login_log.email}}</b> · {{latest.authentication_result}} · {{latest.login_log.ip_address}} · {{latest.created_at}}</p><p>ML: {{latest.ml_classification}} ({{'%.3f'|format(latest.ml_risk_score)}}) · Derived risk: {{'%.3f'|format(latest.derived_risk_score)}} · <span class="sev {{latest.severity}}">{{latest.severity|upper}}</span></p><p>Indicators: {{latest.indicators}}</p></section>{% else %}<section class=panel>No authentication events have been recorded yet.</section>{% endif %}<section class=panel><h2>Safe demonstration</h2><p class=muted>Generates local sample authentication telemetry through this same pipeline; no external system is contacted.</p><form method=post action="{{url_for('main.simulate_authentication')}}"><input type=hidden name=csrf_token value="{{csrf_token()}}"><button name=profile value=failed_burst>Simulate failed burst</button> <button name=profile value=new_device>Simulate new device</button> <button name=profile value=off_hours>Simulate off-hours login</button></form></section><section class=panel><h2>Recent Security Events</h2><table><tr><th>Time</th><th>User</th><th>Result</th><th>ML</th><th>Risk</th><th>Severity</th><th>Indicators</th></tr>{% for e in events %}<tr><td>{{e.created_at}}</td><td>{{e.login_log.email}}</td><td>{{e.authentication_result}}</td><td>{{e.ml_classification}}</td><td>{{'%.3f'|format(e.derived_risk_score)}}</td><td class="sev {{e.severity}}">{{e.severity|upper}}</td><td>{{e.indicators}}</td></tr>{% endfor %}</table></section></main>"""


@main_bp.route("/ids/predict", methods=["GET", "POST"])
@login_required
def threat_analysis():
    if request.method == "POST":
        flash("The latest authentication telemetry is analyzed automatically.")
        return redirect(url_for("main.threat_analysis"))
    events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(25).all()
    if not current_user.is_admin():
        events = [event for event in events if event.user_id == current_user.id]
    return render_template_string(THREAT_ANALYSIS_TEMPLATE, events=events, latest=events[0] if events else None)


@main_bp.route("/ids/simulate", methods=["POST"])
@login_required
def simulate_authentication():
    profiles = {"failed_burst": (False, "198.51.100.77", ["repeated_authentication_attempts", "demo_failed_burst"]), "new_device": (True, "203.0.113.21", ["unrecognized_device", "demo_new_device"]), "off_hours": (True, "203.0.113.33", ["unusual_login_time", "demo_off_hours"])}
    profile = request.form.get("profile", "failed_burst")
    success, ip_address, indicators = profiles.get(profile, profiles["failed_burst"])
    fails, hour = current_user.failed_login_count + (5 if profile == "failed_burst" else 0), (2 if profile == "off_hours" else datetime.now(timezone.utc).hour)
    risk = IntrusionPredictor(current_app.config["MODEL_PATH"]).predict_risk([float(hour), float(fails), 0.0, 0.0, float(profile == "new_device")])
    log = LoginLog(user_id=current_user.id, email=current_user.email, ip_address=ip_address, user_agent="SOC safe demonstration", success=success, risk_score=risk, suspicious_indicators=";".join(indicators))
    db.session.add(log); db.session.flush()
    SecurityService.analyze_authentication(login_log_id=log.id, user_id=current_user.id, success=success, ml_risk_score=risk, indicators=indicators)
    SecurityService.audit(current_user.id, "SAFE_TELEMETRY_SIMULATION", "LoginLog", str(log.id), profile)
    db.session.commit(); flash("Safe demonstration telemetry was generated and analyzed.")
    return redirect(url_for("main.threat_analysis"))


@main_bp.route("/ids/legacy-predict", methods=["GET", "POST"])
@login_required
def predict_ids():

    result = None
    risk_score = None
    threat_level = None
    indicators = []

    if request.method == "POST":

        login_hour = float(
            request.form.get("login_hour", "12")
        )

        preceding_fails = float(
            request.form.get("preceding_fails", "0")
        )

        suspicious_ip = (
            request.form.get("suspicious_ip") == "on"
        )

        country_mismatch = (
            request.form.get("country_mismatch") == "on"
        )

        new_device = (
            request.form.get("new_device") == "on"
        )

        features = [
            login_hour,
            preceding_fails,
            float(1 if suspicious_ip else 0),
            float(1 if country_mismatch else 0),
            float(1 if new_device else 0),
        ]

        predictor = IntrusionPredictor(
            current_app.config["MODEL_PATH"]
        )

        risk_score = predictor.predict_risk(features)

        result = (
            "Attack"
            if risk_score >= 0.5
            else "Normal"
        )

        # --------------------------------------------------
        # Build human-readable security indicators
        # --------------------------------------------------

        if suspicious_ip:
            indicators.append("SUSPICIOUS_IP")

        if country_mismatch:
            indicators.append("COUNTRY_MISMATCH")

        if new_device:
            indicators.append("NEW_DEVICE")

        if preceding_fails > 0:
            indicators.append(
                f"PRECEDING_FAILURES:{int(preceding_fails)}"
            )

        if login_hour < 6 or login_hour >= 23:
            indicators.append("UNUSUAL_LOGIN_HOUR")

        indicator_text = (
            ";".join(indicators)
            if indicators
            else "none"
        )

        # --------------------------------------------------
        # Determine threat level
        # --------------------------------------------------

        if risk_score >= 0.8:
            threat_level = "Critical"

        elif risk_score >= 0.5:
            threat_level = "Medium"

        else:
            threat_level = "Low"

        # --------------------------------------------------
        # Record IDS prediction in audit trail
        # --------------------------------------------------

        SecurityService.audit(
            current_user.id,
            "IDS_PREDICTION",
            "IDS_ANALYSIS",
            "MANUAL",
            (
                f"Prediction={result}; "
                f"risk_score={risk_score:.4f}; "
                f"threat_level={threat_level}; "
                f"indicators={indicator_text}."
            ),
        )

        # --------------------------------------------------
        # Create a real security alert for detected attacks
        # --------------------------------------------------

        if result == "Attack":

            if risk_score >= 0.8:
                severity = "high"
            else:
                severity = "medium"

            SecurityService.create_alert(
                user_id=current_user.id,
                login_log_id=None,
                incident_class="IDS_MODEL_DETECTION",
                severity=severity,
                description=(
                    "IDS model detected potentially malicious "
                    f"authentication activity. "
                    f"Risk score: {risk_score:.4f}. "
                    f"Threat level: {threat_level}. "
                    f"Indicators: {indicator_text}."
                ),
            )

        db.session.commit()

    return render_template_string(
        """
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>IDS Threat Analysis</title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: #050f13;
            color: #e8f8ff;
            font-family: Arial, Helvetica, sans-serif;
        }

        .page {
            max-width: 1100px;
            margin: 0 auto;
            padding: 45px 24px 70px;
        }

        .eyebrow {
            color: #00d9ff;
            font-size: 12px;
            font-weight: bold;
            letter-spacing: 3px;
            text-transform: uppercase;
        }

        .title {
            font-size: 32px;
            font-weight: 700;
            margin-top: 8px;
            margin-bottom: 8px;
        }

        .subtitle {
            color: #6d9bab;
            margin-bottom: 28px;
        }

        .panel {
            background: #09181d;
            border: 1px solid #173a44;
            border-radius: 14px;
            overflow: hidden;
            margin-bottom: 24px;
        }

        .panel-header {
            padding: 20px;
            border-bottom: 1px solid #173a44;
        }

        .panel-header h3 {
            margin: 0;
            font-size: 16px;
            letter-spacing: .5px;
        }

        .panel-header p {
            margin: 6px 0 0;
            color: #7197a6;
            font-size: 13px;
        }

        .panel-body {
            padding: 24px;
        }

        .telemetry {
            background: #030a0d;
            border: 1px solid #112d35;
            padding: 18px;
            margin-bottom: 24px;
            font-family: Consolas, monospace;
            font-size: 13px;
            line-height: 2;
            color: #00e676;
        }

        .form-label {
            color: #75aabd;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .form-control {
            background: #07151a;
            border: 1px solid #1c4652;
            color: #e8f8ff;
            min-height: 44px;
        }

        .form-control:focus {
            background: #07151a;
            color: #ffffff;
            border-color: #00d9ff;
            box-shadow: 0 0 0 2px rgba(0,217,255,.12);
        }

        .indicator-box {
            background: #07151a;
            border: 1px solid #173a44;
            border-radius: 8px;
            padding: 15px;
            height: 100%;
        }

        .form-check-input {
            background-color: #07151a;
            border-color: #2b5661;
        }

        .form-check-input:checked {
            background-color: #00a9d4;
            border-color: #00a9d4;
        }

        .form-check-label {
            color: #dceff5;
        }

        .btn-analyze {
            background: transparent;
            border: 1px solid #00d9ff;
            color: #00d9ff;
            padding: 12px 22px;
            font-weight: bold;
            letter-spacing: 1px;
        }

        .btn-analyze:hover {
            background: #00d9ff;
            color: #001014;
        }

        .btn-back {
            display: inline-block;
            color: #00d9ff;
            border: 1px solid #174a58;
            padding: 9px 15px;
            text-decoration: none;
            border-radius: 7px;
            margin-bottom: 24px;
        }

        .btn-back:hover {
            color: #ffffff;
            border-color: #00d9ff;
        }

        .result-panel {
            border-color: #244650;
        }

        .result-body {
            padding: 28px;
        }

        .result-grid {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 20px;
            align-items: center;
        }

        .result-label {
            color: #70a6b8;
            font-size: 12px;
            letter-spacing: 2px;
            text-transform: uppercase;
        }

        .attack-text {
            color: #ff4754;
            font-size: 29px;
            font-weight: 800;
            margin-top: 8px;
        }

        .normal-text {
            color: #00e676;
            font-size: 29px;
            font-weight: 800;
            margin-top: 8px;
        }

        .risk-number {
            color: #00d9ff;
            font-size: 34px;
            font-weight: 800;
            text-align: right;
        }

        .risk-bar {
            height: 8px;
            background: #122b32;
            border-radius: 10px;
            overflow: hidden;
            margin: 24px 0;
        }

        .risk-fill {
            height: 100%;
            border-radius: 10px;
        }

        .risk-danger {
            background: #ff4754;
        }

        .risk-warning {
            background: #ffd21f;
        }

        .risk-safe {
            background: #00e676;
        }

        .detail-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
        }

        .detail-card {
            background: #07151a;
            border: 1px solid #173a44;
            border-radius: 8px;
            padding: 16px;
        }

        .detail-title {
            color: #5f9aad;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }

        .detail-value {
            color: #ffffff;
            font-size: 16px;
            font-weight: bold;
        }

        .detected {
            color: #ff4754;
        }

        .clear {
            color: #00e676;
        }

        .response-box {
            margin-top: 20px;
            padding: 17px;
            background: #061116;
            border-left: 3px solid #00d9ff;
            color: #b9d9e3;
            line-height: 1.7;
            font-size: 13px;
        }

        @media (max-width: 768px) {

            .result-grid {
                grid-template-columns: 1fr;
            }

            .risk-number {
                text-align: left;
            }

            .detail-grid {
                grid-template-columns: 1fr;
            }

            .title {
                font-size: 27px;
            }

        }

    </style>

</head>


<body>

<div class="page">

    <div class="eyebrow">
        Intrusion Detection System
    </div>

    <div class="title">
        IDS Threat Analysis
    </div>

    <div class="subtitle">
        Analyze authentication telemetry using the trained intrusion detection model.
    </div>


    <a
        href="{{ url_for('main.dashboard') }}"
        class="btn-back"
    >
        ← BACK TO DASHBOARD
    </a>


    <div class="panel">

        <div class="panel-header">

            <h3>
                THREAT ANALYSIS ENGINE
            </h3>

            <p>
                Configure authentication indicators
            </p>

        </div>


        <div class="panel-body">

            <div class="telemetry">

                [OK] IDS prediction engine loaded<br>
                [OK] Machine learning model available<br>
                [OK] Authentication feature pipeline ready

            </div>


            <form method="post">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="{{ csrf_token() }}"
                >


                <div class="row">

                    <div class="col-md-6 mb-4">

                        <label class="form-label">
                            Login Hour
                        </label>

                        <input
                            class="form-control"
                            name="login_hour"
                            type="number"
                            min="0"
                            max="23"
                            value="12"
                            required
                        >

                    </div>


                    <div class="col-md-6 mb-4">

                        <label class="form-label">
                            Previous Failed Attempts
                        </label>

                        <input
                            class="form-control"
                            name="preceding_fails"
                            type="number"
                            min="0"
                            max="20"
                            value="0"
                            required
                        >

                    </div>

                </div>


                <div class="row mb-4">

                    <div class="col-md-4 mb-3">

                        <div class="indicator-box">

                            <div class="form-check">

                                <input
                                    class="form-check-input"
                                    name="suspicious_ip"
                                    type="checkbox"
                                    id="suspicious_ip"
                                >

                                <label
                                    class="form-check-label"
                                    for="suspicious_ip"
                                >
                                    Suspicious IP
                                </label>

                            </div>

                        </div>

                    </div>


                    <div class="col-md-4 mb-3">

                        <div class="indicator-box">

                            <div class="form-check">

                                <input
                                    class="form-check-input"
                                    name="country_mismatch"
                                    type="checkbox"
                                    id="country_mismatch"
                                >

                                <label
                                    class="form-check-label"
                                    for="country_mismatch"
                                >
                                    Country Mismatch
                                </label>

                            </div>

                        </div>

                    </div>


                    <div class="col-md-4 mb-3">

                        <div class="indicator-box">

                            <div class="form-check">

                                <input
                                    class="form-check-input"
                                    name="new_device"
                                    type="checkbox"
                                    id="new_device"
                                >

                                <label
                                    class="form-check-label"
                                    for="new_device"
                                >
                                    New Device
                                </label>

                            </div>

                        </div>

                    </div>

                </div>


                <button
                    type="submit"
                    class="btn btn-analyze"
                >
                    ANALYZE THREAT
                </button>

            </form>

        </div>

    </div>


    {% if result %}

    <div class="panel result-panel">

        <div class="panel-header">

            <h3>
                ANALYSIS RESULT
            </h3>

        </div>


        <div class="result-body">

            <div class="result-grid">

                <div>

                    <div class="result-label">
                        Detection Status
                    </div>


                    {% if result == "Attack" %}

                        <div class="attack-text">
                            ⚠ Attack Detected
                        </div>

                    {% else %}

                        <div class="normal-text">
                            ✓ Normal Activity
                        </div>

                    {% endif %}

                </div>


                <div>

                    <div class="result-label">
                        Risk Score
                    </div>

                    <div class="risk-number">
                        {{ "%.3f"|format(risk_score) }}
                    </div>

                </div>

            </div>


            {% if risk_score >= 0.8 %}

                <div class="risk-bar">
                    <div
                        class="risk-fill risk-danger"
                        style="width: {{ (risk_score * 100)|round(1) }}%;"
                    ></div>
                </div>

            {% elif risk_score >= 0.5 %}

                <div class="risk-bar">
                    <div
                        class="risk-fill risk-warning"
                        style="width: {{ (risk_score * 100)|round(1) }}%;"
                    ></div>
                </div>

            {% else %}

                <div class="risk-bar">
                    <div
                        class="risk-fill risk-safe"
                        style="width: {{ (risk_score * 100)|round(1) }}%;"
                    ></div>
                </div>

            {% endif %}


            <div class="detail-grid">

                <div class="detail-card">

                    <div class="detail-title">
                        Login Hour
                    </div>

                    <div class="detail-value">
                        {{ request.form.get("login_hour", "12") }}:00
                    </div>

                </div>


                <div class="detail-card">

                    <div class="detail-title">
                        Failed Attempts
                    </div>

                    <div class="detail-value">
                        {{ request.form.get("preceding_fails", "0") }}
                    </div>

                </div>


                <div class="detail-card">

                    <div class="detail-title">
                        Suspicious IP
                    </div>

                    {% if request.form.get("suspicious_ip") == "on" %}

                        <div class="detail-value detected">
                            DETECTED
                        </div>

                    {% else %}

                        <div class="detail-value clear">
                            CLEAR
                        </div>

                    {% endif %}

                </div>


                <div class="detail-card">

                    <div class="detail-title">
                        Country Mismatch
                    </div>

                    {% if request.form.get("country_mismatch") == "on" %}

                        <div class="detail-value detected">
                            DETECTED
                        </div>

                    {% else %}

                        <div class="detail-value clear">
                            CLEAR
                        </div>

                    {% endif %}

                </div>


                <div class="detail-card">

                    <div class="detail-title">
                        New Device
                    </div>

                    {% if request.form.get("new_device") == "on" %}

                        <div class="detail-value detected">
                            DETECTED
                        </div>

                    {% else %}

                        <div class="detail-value clear">
                            CLEAR
                        </div>

                    {% endif %}

                </div>


                <div class="detail-card">

                    <div class="detail-title">
                        Threat Level
                    </div>

                    <div class="detail-value">

                        {% if threat_level == "Critical" %}

                            <span class="detected">
                                CRITICAL
                            </span>

                        {% elif threat_level == "Medium" %}

                            <span style="color:#ffd21f;">
                                MEDIUM
                            </span>

                        {% else %}

                            <span class="clear">
                                LOW
                            </span>

                        {% endif %}

                    </div>

                </div>

            </div>


            {% if result == "Attack" %}

                <div class="response-box">

                    <strong style="color:#00d9ff;">
                        Security Response:
                    </strong>

                    The authentication activity has been classified
                    as potentially malicious by the IDS model.

                    The prediction has been recorded in the security
                    audit trail and an IDS security alert has been
                    created for administrator investigation.

                </div>

            {% else %}

                <div class="response-box">

                    <strong style="color:#00e676;">
                        Security Response:
                    </strong>

                    No malicious activity was detected by the IDS model.
                    The prediction has been recorded in the security
                    audit trail.

                </div>

            {% endif %}

        </div>

    </div>

    {% endif %}


</div>

</body>

</html>
        """,
        result=result,
        risk_score=risk_score,
        threat_level=threat_level,
        indicators=indicators,
    )

