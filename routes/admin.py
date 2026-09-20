from datetime import datetime, timezone

from flask import (
    Blueprint,
    Response,
    abort,
    redirect,
    render_template_string,
    url_for,
)
from flask_login import current_user, login_required

from extensions import db
from models.alert import SecurityAlert
from models.log import AuditLog, LoginLog
from models.user import User
from services.report_service import ReportService
from services.security_service import SecurityService


admin_bp = Blueprint("admin", __name__)


def _require_admin() -> None:
    if not current_user.is_authenticated or not current_user.is_admin():
        abort(403)


# ============================================================
# SOC ADMIN DASHBOARD
# ============================================================

@admin_bp.route("/")
@login_required
def portal():
    _require_admin()

    # --------------------------------------------------------
    # Dashboard statistics
    # --------------------------------------------------------
    totals = {
        "users": User.query.count(),
        "login_logs": LoginLog.query.count(),
        "open_alerts": SecurityAlert.query.filter_by(
            is_resolved=False
        ).count(),
        "audit_logs": AuditLog.query.count(),
    }

    # --------------------------------------------------------
    # Login telemetry
    # --------------------------------------------------------
    login_logs = (
        LoginLog.query
        .order_by(LoginLog.created_at.desc())
        .limit(25)
        .all()
    )

    successful_logins = LoginLog.query.filter_by(success=True).count()
    failed_logins = LoginLog.query.filter_by(success=False).count()

    # --------------------------------------------------------
    # Security alerts
    # --------------------------------------------------------
    alerts = (
        SecurityAlert.query
        .order_by(SecurityAlert.created_at.desc())
        .limit(50)
        .all()
    )

    high_alerts = SecurityAlert.query.filter_by(
        severity="high",
        is_resolved=False
    ).count()

    medium_alerts = SecurityAlert.query.filter_by(
        severity="medium",
        is_resolved=False
    ).count()

    low_alerts = SecurityAlert.query.filter_by(
        severity="low",
        is_resolved=False
    ).count()

    # --------------------------------------------------------
    # Users
    # --------------------------------------------------------
    users = (
        User.query
        .order_by(User.created_at.desc())
        .all()
    )

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

    <title>SOC Command Center</title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >

    <style>

        /* ====================================================
           GLOBAL
           ==================================================== */

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: #061014;
            color: #e8f4f7;
            font-family:
                Arial,
                Helvetica,
                sans-serif;
        }

        a {
            text-decoration: none;
        }

        .container {
            max-width: 1500px;
        }


        /* ====================================================
           HEADER
           ==================================================== */

        .soc-header {
            background: #081217;
            border-bottom: 1px solid #18333b;
            padding: 20px 30px;
        }

        .soc-brand {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .shield {
            width: 44px;
            height: 44px;
            border: 1px solid #00d9ff;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #00d9ff;
            font-size: 22px;
        }

        .brand-title {
            font-size: 20px;
            font-weight: 700;
            letter-spacing: 1px;
            color: #e6f1f4;
        }

        .brand-subtitle {
            font-size: 11px;
            letter-spacing: 2px;
            color: #668d99;
            margin-top: 3px;
        }

        .system-online {
            color: #16d879;
            font-weight: 700;
            font-size: 13px;
            letter-spacing: 1px;
        }

        .online-dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #16d879;
            margin-right: 8px;
            box-shadow: 0 0 10px #16d879;
        }


        /* ====================================================
           PAGE
           ==================================================== */

        .page-wrapper {
            padding: 35px 0 70px;
        }

        .section-label {
            color: #5795a5;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 3px;
            margin-bottom: 12px;
        }

        .page-title {
            font-size: 30px;
            font-weight: 600;
            margin-bottom: 28px;
            color: #eaf5f7;
        }


        /* ====================================================
           ACTION BUTTONS
           ==================================================== */

        .action-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 9px;
            justify-content: flex-end;
            margin-bottom: 28px;
        }

        .soc-btn {
            border-radius: 7px;
            padding: 9px 16px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: .5px;
            background: transparent;
        }

        .btn-ids {
            color: #00d9ff;
            border: 1px solid #075d6c;
        }

        .btn-ids:hover {
            background: #06333d;
            color: #ffffff;
        }

        .btn-export {
            color: #16d879;
            border: 1px solid #12613f;
        }

        .btn-export:hover {
            background: #073524;
            color: #ffffff;
        }

        .btn-alert {
            color: #ffc400;
            border: 1px solid #665300;
        }

        .btn-alert:hover {
            background: #3b3100;
            color: #ffffff;
        }

        .btn-logout {
            color: #ff6673;
            border: 1px solid #71303a;
        }

        .btn-logout:hover {
            background: #3d151b;
            color: #ffffff;
        }


        /* ====================================================
           STAT CARDS
           ==================================================== */

        .stat-card {
            height: 145px;
            background: #0a191e;
            border: 1px solid #173740;
            border-radius: 13px;
            padding: 24px;
        }

        .stat-label {
            color: #6f9eaa;
            font-size: 12px;
            letter-spacing: 1px;
            margin-bottom: 15px;
        }

        .stat-number {
            font-size: 31px;
            font-weight: 700;
            line-height: 1;
        }

        .stat-number.cyan {
            color: #00d9ff;
        }

        .stat-number.white {
            color: #eaf5f7;
        }

        .stat-number.red {
            color: #ff4f5e;
        }

        .stat-number.green {
            color: #16d879;
        }

        .stat-description {
            color: #668d99;
            font-size: 12px;
            margin-top: 14px;
        }


        /* ====================================================
           PANELS
           ==================================================== */

        .soc-panel {
            background: #09181d;
            border: 1px solid #173740;
            border-radius: 13px;
            overflow: hidden;
            margin-top: 25px;
        }

        .panel-header {
            min-height: 58px;
            padding: 18px 20px;
            border-bottom: 1px solid #173740;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .panel-title {
            color: #e6f3f6;
            font-size: 14px;
            font-weight: 700;
            letter-spacing: .5px;
            text-transform: uppercase;
        }

        .panel-subtitle {
            color: #628692;
            font-size: 12px;
            margin-top: 5px;
        }

        .panel-body {
            padding: 20px;
        }


        /* ====================================================
           THREAT SEVERITY
           ==================================================== */

        .severity-row {
            margin-bottom: 22px;
        }

        .severity-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 9px;
        }

        .severity-name {
            color: #7c9ba4;
            font-size: 13px;
        }

        .severity-count {
            font-size: 14px;
            font-weight: 700;
        }

        .severity-bar {
            height: 7px;
            background: #10272e;
            border-radius: 10px;
            overflow: hidden;
        }

        .severity-fill {
            height: 100%;
            border-radius: 10px;
        }

        .high-fill {
            background: #ff4f5e;
        }

        .medium-fill {
            background: #ffc400;
        }

        .low-fill {
            background: #16c879;
        }


        /* ====================================================
           AUTHENTICATION STATUS
           ==================================================== */

        .auth-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 13px 5px;
        }

        .auth-label {
            font-size: 16px;
            color: #dcebef;
        }

        .auth-value {
            font-size: 17px;
            font-weight: 700;
        }

        .auth-success {
            color: #16d879;
        }

        .auth-failed {
            color: #ff4f5e;
        }

        .auth-audit {
            color: #00d9ff;
        }


        /* ====================================================
           SYSTEM TELEMETRY
           ==================================================== */

        .terminal {
            background: #03090b;
            min-height: 190px;
            padding: 20px;
            font-family: Consolas, monospace;
            font-size: 12px;
            line-height: 2;
            color: #00d9ff;
        }

        .terminal-ok {
            color: #16d879;
        }


        /* ====================================================
           TABLES
           ==================================================== */

        .table-wrapper {
            overflow-x: auto;
        }

        .soc-table {
            width: 100%;
            margin: 0;
            border-collapse: collapse;
            color: #e5f0f3;
        }

        .soc-table thead {
            background: #071419;
        }

        .soc-table th {
            color: #6794a0;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            padding: 14px 16px;
            border-bottom: 1px solid #173740;
            white-space: nowrap;
        }

        .soc-table td {
            padding: 15px 16px;
            font-size: 12px;
            border-bottom: 1px solid #173740;
            vertical-align: middle;
        }

        .soc-table tbody tr:hover {
            background: #0d2026;
        }

        .user-email {
            color: #e9f4f7;
            font-weight: 500;
        }

        .ip-address {
            color: #88aab3;
            font-family: Consolas, monospace;
        }

        .risk-low {
            color: #16d879;
            font-weight: 700;
        }

        .risk-medium {
            color: #ffc400;
            font-weight: 700;
        }

        .risk-high {
            color: #ff4f5e;
            font-weight: 700;
        }


        /* ====================================================
           DARK STATUS BADGES
           ==================================================== */

        .status-badge {
            display: inline-block;
            min-width: 65px;
            text-align: center;
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: .7px;
        }

        /* SUCCESS */
        .status-success {
            background: #075d3b !important;
            color: #ffffff !important;
            border: 1px solid #16d879 !important;
        }

        /* FAILED */
        .status-failed {
            background: #7d1727 !important;
            color: #ffffff !important;
            border: 1px solid #ff4f5e !important;
        }

        /* ACTIVE */
        .status-active {
            background: #075d3b !important;
            color: #ffffff !important;
            border: 1px solid #16d879 !important;
        }

        /* OPEN */
        .status-open {
            background: #6f1723 !important;
            color: #ffffff !important;
            border: 1px solid #ff4f5e !important;
        }

        /* RESOLVED */
        .status-resolved {
            background: #075d3b !important;
            color: #ffffff !important;
            border: 1px solid #16d879 !important;
        }

        /* LOCKED */
        .status-locked {
            background: #7d1727 !important;
            color: #ffffff !important;
            border: 1px solid #ff4f5e !important;
        }


        /* ====================================================
           SEVERITY BADGES
           ==================================================== */

        .severity-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 6px;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: .7px;
        }

        .severity-high {
            background: #7d1727 !important;
            color: #ffffff !important;
            border: 1px solid #ff4f5e !important;
        }

        .severity-medium {
            background: #735700 !important;
            color: #ffffff !important;
            border: 1px solid #ffc400 !important;
        }

        .severity-low {
            background: #075d3b !important;
            color: #ffffff !important;
            border: 1px solid #16d879 !important;
        }


        /* ====================================================
           ACTION BUTTONS INSIDE TABLE
           ==================================================== */

        .resolve-btn {
            border-radius: 6px;
            padding: 6px 12px;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: .5px;
            background: transparent;
        }

        .resolve-btn.open-action {
            color: #16d879;
            border: 1px solid #16d879;
        }

        .resolve-btn.open-action:hover {
            background: #075d3b;
            color: #ffffff;
        }

        .resolve-btn.reopen-action {
            color: #ffc400;
            border: 1px solid #ffc400;
        }

        .resolve-btn.reopen-action:hover {
            background: #735700;
            color: #ffffff;
        }


        /* ====================================================
           LIVE DATA
           ==================================================== */

        .live-badge {
            color: #16d879;
            background: #073524;
            border: 1px solid #12613f;
            border-radius: 6px;
            padding: 7px 11px;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: .7px;
        }


        /* ====================================================
           MOBILE
           ==================================================== */

        @media (max-width: 768px) {

            .soc-header {
                padding: 16px;
            }

            .page-wrapper {
                padding: 25px 12px 50px;
            }

            .page-title {
                font-size: 24px;
            }

            .action-bar {
                justify-content: flex-start;
            }

            .stat-card {
                margin-bottom: 15px;
            }

            .panel-header {
                align-items: flex-start;
                gap: 10px;
            }

        }

    </style>

</head>


<body>


<!-- ========================================================
     HEADER
     ======================================================== -->

<header class="soc-header">

    <div class="container-fluid">

        <div class="d-flex justify-content-between align-items-center">

            <div class="soc-brand">

                <div class="shield">
                    🛡
                </div>

                <div>

                    <div class="brand-title">
                        SECURITY OPERATIONS CENTER
                    </div>

                    <div class="brand-subtitle">
                        AI-POWERED AUTHENTICATION &amp; INTRUSION DETECTION
                    </div>

                </div>

            </div>


            <div class="system-online">

                <span class="online-dot"></span>

                SYSTEM ONLINE

            </div>

        </div>

    </div>

</header>


<!-- ========================================================
     MAIN
     ======================================================== -->

<main class="container page-wrapper">


    <div class="section-label">
        SECURITY MONITORING
    </div>


    <div class="d-flex justify-content-between align-items-center flex-wrap gap-3">

        <h1 class="page-title mb-0">
            SOC Command Center
        </h1>


        <div class="action-bar mb-0">

            <a
                href="{{ url_for('main.threat_analysis') }}"
                class="soc-btn btn-ids"
            >
                IDS ANALYSIS
            </a>


            <a
                href="{{ url_for('admin.export_login_logs') }}"
                class="soc-btn btn-export"
            >
                EXPORT LOGS
            </a>


            <a
                href="{{ url_for('admin.export_alerts') }}"
                class="soc-btn btn-alert"
            >
                EXPORT ALERTS
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

                <button
                    type="submit"
                    class="soc-btn btn-logout"
                >
                    LOGOUT
                </button>

            </form>

        </div>

    </div>


    <!-- ====================================================
         STATISTICS
         ==================================================== -->

    <div class="row g-3 mt-3">

        <div class="col-lg-3 col-md-6">

            <div class="stat-card">

                <div class="stat-label">
                    MONITORED USERS
                </div>

                <div class="stat-number cyan">
                    {{ totals.users }}
                </div>

                <div class="stat-description">
                    Registered security principals
                </div>

            </div>

        </div>


        <div class="col-lg-3 col-md-6">

            <div class="stat-card">

                <div class="stat-label">
                    LOGIN EVENTS
                </div>

                <div class="stat-number white">
                    {{ totals.login_logs }}
                </div>

                <div class="stat-description">
                    Authentication telemetry collected
                </div>

            </div>

        </div>


        <div class="col-lg-3 col-md-6">

            <div class="stat-card">

                <div class="stat-label">
                    OPEN THREATS
                </div>

                <div class="stat-number red">
                    {{ totals.open_alerts }}
                </div>

                <div class="stat-description">
                    Active unresolved alerts
                </div>

            </div>

        </div>


        <div class="col-lg-3 col-md-6">

            <div class="stat-card">

                <div class="stat-label">
                    AUDIT EVENTS
                </div>

                <div class="stat-number green">
                    {{ totals.audit_logs }}
                </div>

                <div class="stat-description">
                    Security actions recorded
                </div>

            </div>

        </div>

    </div>


    <!-- ====================================================
         MONITORING ROW
         ==================================================== -->

    <div class="row g-3 mt-1">


        <!-- THREAT SEVERITY -->

        <div class="col-lg-4">

            <div class="soc-panel">

                <div class="panel-header">

                    <div class="panel-title">
                        Threat Severity
                    </div>

                    <div class="status-badge status-resolved">
                        OPEN
                    </div>

                </div>


                <div class="panel-body">

                    <div class="severity-row">

                        <div class="severity-header">

                            <span class="severity-name">
                                HIGH
                            </span>

                            <span class="severity-count"
                                  style="color:#ff4f5e;">
                                {{ high_alerts }}
                            </span>

                        </div>

                        <div class="severity-bar">

                            <div
                                class="severity-fill high-fill"
                                style="width:
                                    {% if totals.open_alerts %}
                                        {{ (high_alerts / totals.open_alerts * 100) | round }}%
                                    {% else %}
                                        0%
                                    {% endif %}
                                "
                            ></div>

                        </div>

                    </div>


                    <div class="severity-row">

                        <div class="severity-header">

                            <span class="severity-name">
                                MEDIUM
                            </span>

                            <span class="severity-count"
                                  style="color:#ffc400;">
                                {{ medium_alerts }}
                            </span>

                        </div>

                        <div class="severity-bar">

                            <div
                                class="severity-fill medium-fill"
                                style="width:
                                    {% if totals.open_alerts %}
                                        {{ (medium_alerts / totals.open_alerts * 100) | round }}%
                                    {% else %}
                                        0%
                                    {% endif %}
                                "
                            ></div>

                        </div>

                    </div>


                    <div class="severity-row mb-0">

                        <div class="severity-header">

                            <span class="severity-name">
                                LOW
                            </span>

                            <span class="severity-count"
                                  style="color:#16d879;">
                                {{ low_alerts }}
                            </span>

                        </div>

                        <div class="severity-bar">

                            <div
                                class="severity-fill low-fill"
                                style="width:
                                    {% if totals.open_alerts %}
                                        {{ (low_alerts / totals.open_alerts * 100) | round }}%
                                    {% else %}
                                        0%
                                    {% endif %}
                                "
                            ></div>

                        </div>

                    </div>

                </div>

            </div>

        </div>


        <!-- AUTHENTICATION STATUS -->

        <div class="col-lg-4">

            <div class="soc-panel">

                <div class="panel-header">

                    <div class="panel-title">
                        Authentication Status
                    </div>

                </div>


                <div class="panel-body">

                    <div class="auth-row">

                        <span class="auth-label">
                            Successful logins
                        </span>

                        <span class="auth-value auth-success">
                            {{ successful_logins }}
                        </span>

                    </div>


                    <div class="auth-row">

                        <span class="auth-label">
                            Failed logins
                        </span>

                        <span class="auth-value auth-failed">
                            {{ failed_logins }}
                        </span>

                    </div>


                    <div class="auth-row">

                        <span class="auth-label">
                            Audit records
                        </span>

                        <span class="auth-value auth-audit">
                            {{ totals.audit_logs }}
                        </span>

                    </div>

                </div>

            </div>

        </div>


        <!-- SYSTEM TELEMETRY -->

        <div class="col-lg-4">

            <div class="soc-panel">

                <div class="panel-header">

                    <div class="panel-title">
                        System Telemetry
                    </div>

                </div>


                <div class="terminal">

                    <div>
                        <span class="terminal-ok">[OK]</span>
                        Authentication service operational
                    </div>

                    <div>
                        <span class="terminal-ok">[OK]</span>
                        IDS prediction engine available
                    </div>

                    <div>
                        <span class="terminal-ok">[OK]</span>
                        Security logging enabled
                    </div>

                    <div>
                        <span class="terminal-ok">[OK]</span>
                        Audit subsystem active
                    </div>

                </div>

            </div>

        </div>

    </div>


    <!-- ====================================================
         RECENT SECURITY EVENTS
         ==================================================== -->

    <div class="soc-panel">

        <div class="panel-header">

            <div>

                <div class="panel-title">
                    Recent Security Events
                </div>

                <div class="panel-subtitle">
                    Latest authentication telemetry
                </div>

            </div>


            <div class="live-badge">
                LIVE DATA
            </div>

        </div>


        <div class="table-wrapper">

            <table class="soc-table">

                <thead>

                    <tr>

                        <th>ID</th>
                        <th>USER</th>
                        <th>IP ADDRESS</th>
                        <th>RESULT</th>
                        <th>RISK</th>
                        <th>INDICATORS</th>
                        <th>TIME</th>

                    </tr>

                </thead>


                <tbody>

                {% for log in login_logs %}

                    <tr>

                        <td>
                            #{{ log.id }}
                        </td>


                        <td class="user-email">
                            {{ log.email }}
                        </td>


                        <td class="ip-address">
                            {{ log.ip_address }}
                        </td>


                        <td>

                            {% if log.success %}

                                <span class="status-badge status-success">
                                    SUCCESS
                                </span>

                            {% else %}

                                <span class="status-badge status-failed">
                                    FAILED
                                </span>

                            {% endif %}

                        </td>


                        <td>

                            {% if log.risk_score >= 0.7 %}

                                <span class="risk-high">
                                    {{ "%.3f"|format(log.risk_score) }}
                                </span>

                            {% elif log.risk_score >= 0.4 %}

                                <span class="risk-medium">
                                    {{ "%.3f"|format(log.risk_score) }}
                                </span>

                            {% else %}

                                <span class="risk-low">
                                    {{ "%.3f"|format(log.risk_score) }}
                                </span>

                            {% endif %}

                        </td>


                        <td>
                            {{ log.suspicious_indicators or "-" }}
                        </td>


                        <td>
                            {{ log.created_at }}
                        </td>

                    </tr>

                {% else %}

                    <tr>

                        <td
                            colspan="7"
                            class="text-center"
                            style="color:#668d99;"
                        >
                            No authentication events recorded.
                        </td>

                    </tr>

                {% endfor %}

                </tbody>

            </table>

        </div>

    </div>


    <!-- ====================================================
         SECURITY ALERT QUEUE
         ==================================================== -->

    <div class="soc-panel">

        <div class="panel-header">

            <div>

                <div class="panel-title">
                    Security Alert Queue
                </div>

                <div class="panel-subtitle">
                    Active and historical intrusion alerts
                </div>

            </div>


            <div class="status-badge status-open">
                {{ totals.open_alerts }} OPEN
            </div>

        </div>


        <div class="table-wrapper">

            <table class="soc-table">

                <thead>

                    <tr>

                        <th>ID</th>
                        <th>SEVERITY</th>
                        <th>INCIDENT</th>
                        <th>DESCRIPTION</th>
                        <th>STATUS</th>
                        <th>CREATED</th>
                        <th>ACTION</th>

                    </tr>

                </thead>


                <tbody>

                {% for alert in alerts %}

                    <tr>

                        <td>
                            #{{ alert.id }}
                        </td>


                        <td>

                            {% if alert.severity == "high" %}

                                <span class="severity-badge severity-high">
                                    HIGH
                                </span>

                            {% elif alert.severity == "medium" %}

                                <span class="severity-badge severity-medium">
                                    MEDIUM
                                </span>

                            {% else %}

                                <span class="severity-badge severity-low">
                                    LOW
                                </span>

                            {% endif %}

                        </td>


                        <td>
                            {{ alert.incident_class }}
                        </td>


                        <td>
                            {{ alert.description }}
                        </td>


                        <td>

                            {% if alert.is_resolved %}

                                <span class="status-badge status-resolved">
                                    RESOLVED
                                </span>

                            {% else %}

                                <span class="status-badge status-open">
                                    OPEN
                                </span>

                            {% endif %}

                        </td>


                        <td>
                            {{ alert.created_at }}
                        </td>


                        <td>

                            <form
                                method="post"
                                action="{{
                                    url_for(
                                        'admin.toggle_alert',
                                        alert_id=alert.id
                                    )
                                }}"
                                style="display:inline;"
                            >

                                <input
                                    type="hidden"
                                    name="csrf_token"
                                    value="{{ csrf_token() }}"
                                >

                                {% if alert.is_resolved %}

                                    <button
                                        type="submit"
                                        class="resolve-btn reopen-action"
                                    >
                                        REOPEN
                                    </button>

                                {% else %}

                                    <button
                                        type="submit"
                                        class="resolve-btn open-action"
                                    >
                                        RESOLVE
                                    </button>

                                {% endif %}

                            </form>

                        </td>

                    </tr>

                {% else %}

                    <tr>

                        <td
                            colspan="7"
                            class="text-center"
                            style="color:#668d99;"
                        >
                            No security alerts recorded.
                        </td>

                    </tr>

                {% endfor %}

                </tbody>

            </table>

        </div>

    </div>


    <!-- ====================================================
         USER MONITORING
         ==================================================== -->

    <div class="soc-panel">

        <div class="panel-header">

            <div>

                <div class="panel-title">
                    User Monitoring
                </div>

                <div class="panel-subtitle">
                    Authentication accounts under monitoring
                </div>

            </div>

        </div>


        <div class="table-wrapper">

            <table class="soc-table">

                <thead>

                    <tr>

                        <th>ID</th>
                        <th>EMAIL</th>
                        <th>ROLE</th>
                        <th>STATUS</th>
                        <th>FAILED ATTEMPTS</th>
                        <th>CREATED</th>

                    </tr>

                </thead>


                <tbody>

                {% for user in users %}

                    <tr>

                        <td>
                            #{{ user.id }}
                        </td>


                        <td class="user-email">
                            {{ user.email }}
                        </td>


                        <td>
                            {{ user.role.name }}
                        </td>


                        <td>

                            {% if user.is_locked %}

                                <span class="status-badge status-locked">
                                    LOCKED
                                </span>

                            {% else %}

                                <span class="status-badge status-active">
                                    ACTIVE
                                </span>

                            {% endif %}

                        </td>


                        <td>

                            {% if user.failed_login_count > 0 %}

                                <span class="risk-high">
                                    {{ user.failed_login_count }}
                                </span>

                            {% else %}

                                <span class="risk-low">
                                    0
                                </span>

                            {% endif %}

                        </td>


                        <td>
                            {{ user.created_at }}
                        </td>

                    </tr>

                {% else %}

                    <tr>

                        <td
                            colspan="6"
                            class="text-center"
                            style="color:#668d99;"
                        >
                            No users found.
                        </td>

                    </tr>

                {% endfor %}

                </tbody>

            </table>

        </div>

    </div>


</main>


</body>
</html>
        """,
        totals=totals,
        alerts=alerts,
        users=users,
        login_logs=login_logs,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        low_alerts=low_alerts,
    )


# ============================================================
# ALERT RESOLVE / REOPEN
# ============================================================

@admin_bp.route(
    "/alerts/<int:alert_id>/toggle",
    methods=["POST"]
)
@login_required
def toggle_alert(alert_id: int):

    _require_admin()

    alert = db.session.get(SecurityAlert, alert_id)

    if alert is None:
        abort(404)

    # Toggle resolution state
    alert.is_resolved = not alert.is_resolved

    if alert.is_resolved:

        alert.resolved_by_user_id = current_user.id

        alert.resolved_at = (
            datetime.now(timezone.utc)
            .replace(tzinfo=None)
        )

    else:

        alert.resolved_by_user_id = None
        alert.resolved_at = None

    # Create audit record
    SecurityService.audit(
        current_user.id,
        "TOGGLE_ALERT_RESOLUTION",
        "SecurityAlert",
        str(alert.id),
        f"Resolution state changed to {alert.is_resolved}.",
    )

    db.session.commit()

    return redirect(url_for("admin.portal"))


# ============================================================
# EXPORT LOGIN LOGS
# ============================================================

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
        for log in (
            LoginLog.query
            .order_by(LoginLog.created_at.desc())
            .all()
        )
    )

    csv_data = ReportService.rows_to_csv(
        [
            "id",
            "user_id",
            "email",
            "ip_address",
            "success",
            "risk_score",
            "suspicious_indicators",
            "created_at",
        ],
        rows,
    )

    return _csv_response(
        csv_data,
        "login-logs.csv"
    )


# ============================================================
# EXPORT ALERTS
# ============================================================

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
        for alert in (
            SecurityAlert.query
            .order_by(SecurityAlert.created_at.desc())
            .all()
        )
    )

    csv_data = ReportService.rows_to_csv(
        [
            "id",
            "user_id",
            "login_log_id",
            "incident_class",
            "severity",
            "description",
            "is_resolved",
            "created_at",
            "resolved_at",
        ],
        rows,
    )

    return _csv_response(
        csv_data,
        "alerts.csv"
    )


# ============================================================
# CSV RESPONSE
# ============================================================

def _csv_response(
    csv_data: str,
    filename: str
) -> Response:

    response = Response(
        csv_data,
        mimetype="text/csv"
    )

    response.headers[
        "Content-Disposition"
    ] = f"attachment; filename={filename}"

    return response

