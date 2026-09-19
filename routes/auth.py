import ipaddress
import re
import smtplib
import hashlib
import secrets
import ssl

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urljoin, urlparse

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

from flask_login import (
    current_user,
    login_user,
    logout_user,
)

from app import db, limiter
from ml.predict import IntrusionPredictor
from models.log import LoginLog, PasswordResetToken
from models.user import Role, User
from services.security_service import SecurityService


# ============================================================
# BLUEPRINT
# ============================================================

auth_bp = Blueprint("auth", __name__)


# Internal delivery states are intentionally safe to log: they contain no
# reset token, URL, SMTP password, or recipient address.
EMAIL_SENT = "EMAIL_SENT"
SMTP_CONNECTION_FAILED = "SMTP_CONNECTION_FAILED"
SMTP_AUTH_FAILED = "SMTP_AUTH_FAILED"
SMTP_RECIPIENT_REJECTED = "SMTP_RECIPIENT_REJECTED"
SMTP_SEND_FAILED = "SMTP_SEND_FAILED"
MAIL_CONFIGURATION_MISSING = "MAIL_CONFIGURATION_MISSING"


# ============================================================
# SECURITY VALIDATION
# ============================================================

PASSWORD_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,128}$"
)

EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# Password reset token lifetime
# ============================================================
# SHARED SOC AUTHENTICATION STYLE
# ============================================================

AUTH_STYLE = """
<style>

    * {
        box-sizing: border-box;
    }

    html,
    body {
        margin: 0;
        padding: 0;
        min-height: 100%;
    }

    body {
        background:
            radial-gradient(
                circle at 50% 15%,
                rgba(0, 217, 255, 0.06),
                transparent 32%
            ),
            linear-gradient(
                135deg,
                #02090c 0%,
                #06161b 48%,
                #02090c 100%
            );

        color: #f4f8fa;

        font-family:
            "Segoe UI",
            Arial,
            sans-serif;

        min-height: 100vh;

        display: flex;
        justify-content: center;
        align-items: center;

        overflow-x: hidden;
    }


    body::before {
        content: "";

        position: fixed;
        inset: 0;

        background-image:
            linear-gradient(
                rgba(0, 214, 255, 0.025) 1px,
                transparent 1px
            ),
            linear-gradient(
                90deg,
                rgba(0, 214, 255, 0.025) 1px,
                transparent 1px
            );

        background-size: 45px 45px;

        pointer-events: none;
    }


    .page {
        width: min(92%, 620px);

        padding: 36px 0;

        position: relative;

        z-index: 1;
    }


    .brand {
        text-align: center;

        margin-bottom: 28px;
    }


    .brand-icon {
        width: 70px;
        height: 70px;

        margin: 0 auto 22px;

        border: 1px solid #00d9ff;

        border-radius: 15px;

        display: flex;

        align-items: center;
        justify-content: center;

        color: #00d9ff;

        box-shadow:
            0 0 18px rgba(0, 217, 255, 0.15),
            inset 0 0 20px rgba(0, 217, 255, 0.04);

        position: relative;
    }


    .brand-icon::before {
        content: "";

        width: 17px;
        height: 24px;

        border: 3px solid #00d9ff;

        transform: rotate(45deg);

        display: block;
    }


    .brand-title {
        margin: 0;

        font-size: 29px;

        font-weight: 700;

        letter-spacing: 0.5px;

        text-transform: uppercase;
    }


    .brand-subtitle {
        margin-top: 10px;

        color: #56b9d3;

        font-size: 13px;

        letter-spacing: 3px;

        text-transform: uppercase;
    }


    .system-status {
        margin-top: 18px;

        color: #00f58b;

        font-size: 12px;

        letter-spacing: 2px;

        text-transform: uppercase;

        display: flex;

        align-items: center;

        justify-content: center;

        gap: 10px;
    }


    .status-dot {
        width: 9px;
        height: 9px;

        border-radius: 50%;

        background: #00f58b;

        box-shadow:
            0 0 8px #00f58b,
            0 0 16px rgba(0, 245, 139, 0.4);
    }


    .auth-card {
        background: rgba(5, 22, 27, 0.94);

        border: 1px solid #164552;

        border-radius: 12px;

        box-shadow:
            0 25px 70px rgba(0, 0, 0, 0.45),
            inset 0 1px 0 rgba(255, 255, 255, 0.02);

        overflow: hidden;
    }


    .card-header {
        padding: 30px 38px 24px;

        border-bottom: 1px solid #153942;
    }


    .eyebrow {
        margin-bottom: 12px;

        color: #00d9ff;

        font-size: 12px;

        font-weight: 600;

        letter-spacing: 2px;

        text-transform: uppercase;
    }


    .card-title {
        margin: 0;

        font-size: 25px;

        font-weight: 700;
    }


    .card-description {
        margin: 10px 0 0;

        color: #6ea5b7;

        font-size: 14px;

        line-height: 1.5;
    }


    .card-body {
        padding: 30px 38px 32px;
    }


    .telemetry {
        background: #02090c;

        border: 1px solid #153942;

        padding: 14px 16px;

        margin-bottom: 25px;
    }


    .telemetry-line {
        font-family:
            Consolas,
            "Courier New",
            monospace;

        color: #00f58b;

        font-size: 11px;

        line-height: 1.8;
    }


    .form-group {
        margin-bottom: 22px;
    }


    label {
        display: block;

        margin-bottom: 8px;

        color: #72c8de;

        font-size: 11px;

        font-weight: 600;

        letter-spacing: 1.5px;

        text-transform: uppercase;
    }


    input {
        width: 100%;

        height: 54px;

        padding: 0 16px;

        background: #061218;

        border: 1px solid #225365;

        border-radius: 6px;

        color: #f4f8fa;

        font-size: 14px;

        outline: none;

        transition:
            border-color 0.2s ease,
            box-shadow 0.2s ease,
            background 0.2s ease;
    }


    input::placeholder {
        color: #477486;
    }


    input:focus {
        background: #07171d;

        border-color: #00d9ff;

        box-shadow:
            0 0 0 2px rgba(0, 217, 255, 0.08),
            0 0 18px rgba(0, 217, 255, 0.08);
    }


    .submit-button {
        width: 100%;

        height: 55px;

        margin-top: 4px;

        border: 1px solid #00d9ff;

        border-radius: 6px;

        background: transparent;

        color: #00d9ff;

        font-size: 13px;

        font-weight: 700;

        letter-spacing: 1.5px;

        cursor: pointer;

        text-transform: uppercase;

        transition:
            background 0.2s ease,
            color 0.2s ease,
            box-shadow 0.2s ease;
    }


    .submit-button:hover {
        background: #00d9ff;

        color: #021015;

        box-shadow:
            0 0 18px rgba(0, 217, 255, 0.25);
    }


    .secondary-button {
        width: 100%;

        height: 52px;

        margin-top: 4px;

        border: 1px solid #236071;

        border-radius: 6px;

        background: transparent;

        color: #78b5c7;

        font-size: 12px;

        font-weight: 600;

        letter-spacing: 1px;

        cursor: pointer;

        text-transform: uppercase;

        transition: all 0.2s ease;
    }


    .secondary-button:hover {
        border-color: #00d9ff;

        color: #00d9ff;
    }


    .forgot-link {
        text-align: right;

        margin-top: -10px;

        margin-bottom: 22px;
    }


    .forgot-link a {
        color: #59b8d2;

        font-size: 12px;

        text-decoration: none;
    }


    .forgot-link a:hover {
        color: #00d9ff;

        text-decoration: underline;
    }


    .divider {
        height: 1px;

        background: #153942;

        margin: 26px 0;
    }


    .account-link {
        text-align: center;

        color: #638fa0;

        font-size: 13px;
    }


    .account-link a {
        color: #00d9ff;

        text-decoration: none;

        margin-left: 6px;
    }


    .account-link a:hover {
        text-decoration: underline;
    }


    .alert {
        padding: 12px 14px;

        margin-bottom: 20px;

        border-radius: 5px;

        font-size: 13px;

        line-height: 1.4;
    }


    .alert-danger,
    .alert-warning {
        background: rgba(255, 61, 91, 0.08);

        border: 1px solid rgba(255, 61, 91, 0.35);

        color: #ff7185;
    }


    .alert-success {
        background: rgba(0, 245, 139, 0.07);

        border: 1px solid rgba(0, 245, 139, 0.3);

        color: #00f58b;
    }


    .reset-link-box {
        background: #02090c;

        border: 1px solid #225365;

        padding: 16px;

        margin-top: 20px;

        word-break: break-all;
    }


    .reset-link-title {
        color: #00d9ff;

        font-size: 11px;

        letter-spacing: 1.5px;

        text-transform: uppercase;

        margin-bottom: 10px;
    }


    .reset-link-box a {
        color: #00f58b;

        font-family:
            Consolas,
            "Courier New",
            monospace;

        font-size: 11px;

        text-decoration: none;
    }


    .reset-link-box a:hover {
        text-decoration: underline;
    }


    .security-footer {
        margin-top: 22px;

        text-align: center;

        color: #397487;

        font-size: 10px;

        letter-spacing: 1.5px;

        text-transform: uppercase;
    }


    @media (max-width: 600px) {

        .page {
            width: 94%;
        }

        .brand-title {
            font-size: 23px;
        }

        .brand-subtitle {
            font-size: 10px;

            letter-spacing: 2px;
        }

        .card-header,
        .card-body {
            padding-left: 24px;

            padding-right: 24px;
        }
    }

</style>
"""


# ============================================================
# LOGIN TEMPLATE
# ============================================================

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>SOC Analyst Login</title>

    {{ style|safe }}

</head>


<body>

<div class="page">


    <div class="brand">

        <div class="brand-icon"></div>

        <h1 class="brand-title">
            Security Operations Center
        </h1>

        <div class="brand-subtitle">
            AI-Powered Authentication & Intrusion Detection
        </div>

        <div class="system-status">

            <span class="status-dot"></span>

            Security System Online

        </div>

    </div>


    <div class="auth-card">


        <div class="card-header">

            <div class="eyebrow">
                Authentication Gateway
            </div>

            <h2 class="card-title">
                Secure Analyst Login
            </h2>

            <p class="card-description">
                Authenticate to access the SOC Command Center.
            </p>

        </div>


        <div class="card-body">


            <div class="telemetry">

                <div class="telemetry-line">
                    [OK] Authentication service operational
                </div>

                <div class="telemetry-line">
                    [OK] IDS prediction engine available
                </div>

                <div class="telemetry-line">
                    [OK] Security logging enabled
                </div>

            </div>


            {% with messages = get_flashed_messages() %}

                {% for message in messages %}

                    <div class="alert alert-danger">
                        {{ message }}
                    </div>

                {% endfor %}

            {% endwith %}


            <form method="post">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="{{ csrf_token() }}"
                >


                <div class="form-group">

                    <label for="email">
                        Email Address
                    </label>

                    <input
                        id="email"
                        name="email"
                        type="email"
                        placeholder="analyst@example.com"
                        autocomplete="username"
                        required
                        autofocus
                    >

                </div>


                <div class="form-group">

                    <label for="password">
                        Password
                    </label>

                    <input
                        id="password"
                        name="password"
                        type="password"
                        placeholder="Enter your password"
                        autocomplete="current-password"
                        required
                    >

                </div>


                <div class="forgot-link">

                    <a href="{{ url_for('auth.forgot_password') }}">
                        Forgot Password?
                    </a>

                </div>


                <button
                    type="submit"
                    class="submit-button"
                >
                    Authenticate & Enter SOC
                </button>

            </form>


            <div class="divider"></div>


            <div class="account-link">

                New security analyst?

                <a href="{{ url_for('auth.register') }}">
                    Create Account
                </a>

            </div>


        </div>

    </div>


    <div class="security-footer">
        Authentication Telemetry & Intrusion Detection Enabled
    </div>


</div>

</body>

</html>
"""


# ============================================================
# REGISTER TEMPLATE
# ============================================================

REGISTER_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>Create Security Analyst Account</title>

    {{ style|safe }}

</head>


<body>

<div class="page">


    <div class="brand">

        <div class="brand-icon"></div>

        <h1 class="brand-title">
            Security Operations Center
        </h1>

        <div class="brand-subtitle">
            AI-Powered Authentication & Intrusion Detection
        </div>

        <div class="system-status">

            <span class="status-dot"></span>

            Security System Online

        </div>

    </div>


    <div class="auth-card">


        <div class="card-header">

            <div class="eyebrow">
                Analyst Provisioning
            </div>

            <h2 class="card-title">
                Create Security Account
            </h2>

            <p class="card-description">
                Register a security analyst account to access
                the SOC Command Center.
            </p>

        </div>


        <div class="card-body">


            <div class="telemetry">

                <div class="telemetry-line">
                    [OK] Authentication gateway available
                </div>

                <div class="telemetry-line">
                    [OK] Security logging enabled
                </div>

                <div class="telemetry-line">
                    [OK] IDS prediction engine ready
                </div>

            </div>


            {% with messages = get_flashed_messages() %}

                {% for message in messages %}

                    <div class="alert alert-warning">
                        {{ message }}
                    </div>

                {% endfor %}

            {% endwith %}


            <form method="post">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="{{ csrf_token() }}"
                >


                <div class="form-group">

                    <label for="email">
                        Email Address
                    </label>

                    <input
                        id="email"
                        name="email"
                        type="email"
                        placeholder="analyst@example.com"
                        autocomplete="email"
                        required
                    >

                </div>


                <div class="form-group">

                    <label for="password">
                        Password
                    </label>

                    <input
                        id="password"
                        name="password"
                        type="password"
                        placeholder="Minimum 12 characters"
                        autocomplete="new-password"
                        required
                    >

                </div>


                <button
                    type="submit"
                    class="submit-button"
                >
                    Provision Analyst Account
                </button>

            </form>


            <div class="divider"></div>


            <div class="account-link">

                Existing security analyst?

                <a href="{{ url_for('auth.login') }}">
                    Authenticate
                </a>

            </div>


        </div>

    </div>


    <div class="security-footer">
        Authentication Telemetry & Intrusion Detection Enabled
    </div>


</div>

</body>

</html>
"""


# ============================================================
# FORGOT PASSWORD TEMPLATE
# ============================================================

FORGOT_PASSWORD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>Password Recovery</title>

    {{ style|safe }}

</head>


<body>

<div class="page">


    <div class="brand">

        <div class="brand-icon"></div>

        <h1 class="brand-title">
            Security Operations Center
        </h1>

        <div class="brand-subtitle">
            AI-Powered Authentication & Intrusion Detection
        </div>

        <div class="system-status">

            <span class="status-dot"></span>

            Security System Online

        </div>

    </div>


    <div class="auth-card">


        <div class="card-header">

            <div class="eyebrow">
                Account Recovery
            </div>

            <h2 class="card-title">
                Reset Analyst Password
            </h2>

            <p class="card-description">
                Enter your registered email address to
                begin the secure password recovery process.
            </p>

        </div>


        <div class="card-body">


            <div class="telemetry">

                <div class="telemetry-line">
                    [OK] Recovery service available
                </div>

                <div class="telemetry-line">
                    [OK] Secure token generation enabled
                </div>

                <div class="telemetry-line">
                    [OK] Token lifetime: 30 minutes
                </div>

            </div>


            {% with messages = get_flashed_messages() %}

                {% for message in messages %}

                    <div class="alert alert-success">
                        {{ message }}
                    </div>

                {% endfor %}

            {% endwith %}


            <form method="post">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="{{ csrf_token() }}"
                >


                <div class="form-group">

                    <label for="email">
                        Registered Email Address
                    </label>

                    <input
                        id="email"
                        name="email"
                        type="email"
                        placeholder="analyst@example.com"
                        autocomplete="email"
                        required
                        autofocus
                    >

                </div>


                <button
                    type="submit"
                    class="submit-button"
                >
                    Generate Recovery Link
                </button>

            </form>


            <div class="divider"></div>


            <div class="account-link">

                Remember your password?

                <a href="{{ url_for('auth.login') }}">
                    Return to Login
                </a>

            </div>


        </div>

    </div>


    <div class="security-footer">
        Secure Account Recovery & Authentication Telemetry Enabled
    </div>


</div>

</body>

</html>
"""


# ============================================================
# RESET PASSWORD TEMPLATE
# ============================================================

RESET_PASSWORD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>Reset Password</title>

    {{ style|safe }}

</head>


<body>

<div class="page">


    <div class="brand">

        <div class="brand-icon"></div>

        <h1 class="brand-title">
            Security Operations Center
        </h1>

        <div class="brand-subtitle">
            AI-Powered Authentication & Intrusion Detection
        </div>

        <div class="system-status">

            <span class="status-dot"></span>

            Security System Online

        </div>

    </div>


    <div class="auth-card">


        <div class="card-header">

            <div class="eyebrow">
                Credential Recovery
            </div>

            <h2 class="card-title">
                Set New Password
            </h2>

            <p class="card-description">
                Create a new password for your security
                analyst account.
            </p>

        </div>


        <div class="card-body">


            <div class="telemetry">

                <div class="telemetry-line">
                    [OK] Recovery token validated
                </div>

                <div class="telemetry-line">
                    [OK] Password reset channel secured
                </div>

                <div class="telemetry-line">
                    [OK] Credential update ready
                </div>

            </div>


            {% with messages = get_flashed_messages() %}

                {% for message in messages %}

                    <div class="alert alert-danger">
                        {{ message }}
                    </div>

                {% endfor %}

            {% endwith %}


            <form method="post">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="{{ csrf_token() }}"
                >


                <div class="form-group">

                    <label for="password">
                        New Password
                    </label>

                    <input
                        id="password"
                        name="password"
                        type="password"
                        placeholder="Minimum 12 characters"
                        autocomplete="new-password"
                        required
                    >

                </div>


                <div class="form-group">

                    <label for="confirm_password">
                        Confirm New Password
                    </label>

                    <input
                        id="confirm_password"
                        name="confirm_password"
                        type="password"
                        placeholder="Re-enter your password"
                        autocomplete="new-password"
                        required
                    >

                </div>


                <button
                    type="submit"
                    class="submit-button"
                >
                    Update Secure Credentials
                </button>

            </form>


            <div class="divider"></div>


            <div class="account-link">

                Remember your password?

                <a href="{{ url_for('auth.login') }}">
                    Return to Login
                </a>

            </div>


        </div>

    </div>


    <div class="security-footer">
        Secure Credential Recovery Enabled
    </div>


</div>

</body>

</html>
"""


# ============================================================
# REGISTER
# ============================================================

@auth_bp.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(
            url_for("main.dashboard")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        # ----------------------------------------------------
        # Validate email
        # ----------------------------------------------------

        if not _valid_email(email):
            current_app.logger.info("Password reset request processed: invalid email format; SMTP not attempted.")

            flash(
                "A valid email address is required."
            )

            return (
                render_template_string(
                    REGISTER_TEMPLATE,
                    style=AUTH_STYLE,
                ),
                400,
            )

        # ----------------------------------------------------
        # Validate password
        # ----------------------------------------------------

        if not PASSWORD_RE.match(password):

            flash(
                "Password must be 12-128 characters "
                "with uppercase, lowercase, number, and symbol."
            )

            return (
                render_template_string(
                    REGISTER_TEMPLATE,
                    style=AUTH_STYLE,
                ),
                400,
            )

        # ----------------------------------------------------
        # Existing account
        # ----------------------------------------------------

        if User.query.filter_by(
            email=email
        ).first() is not None:

            flash(
                "Account already exists."
            )

            return (
                render_template_string(
                    REGISTER_TEMPLATE,
                    style=AUTH_STYLE,
                ),
                409,
            )

        # ----------------------------------------------------
        # Analyst role
        # ----------------------------------------------------

        role = Role.query.filter_by(
            name="analyst"
        ).first()

        if role is None:

            role = Role(
                name="analyst",
                description="Standard telemetry analyst",
            )

            db.session.add(role)

            db.session.flush()

        # ----------------------------------------------------
        # Create account
        # ----------------------------------------------------

        user = User(
            email=email,
            role=role,
        )

        user.set_password(password)

        db.session.add(user)

        db.session.flush()

        # ----------------------------------------------------
        # Audit registration
        # ----------------------------------------------------

        SecurityService.audit(
            user.id,
            "REGISTER",
            "User",
            str(user.id),
            "Self-service account registration.",
        )

        db.session.commit()

        # ----------------------------------------------------
        # Login after registration
        # ----------------------------------------------------

        session.permanent = True

        login_user(user)

        return redirect(
            url_for("main.dashboard")
        )

    return render_template_string(
        REGISTER_TEMPLATE,
        style=AUTH_STYLE,
    )


# ============================================================
# LOGIN
# ============================================================

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(
    lambda: current_app.config["LOGIN_RATE_LIMIT"],
    methods=["POST"],
)
def login():

    if current_user.is_authenticated:
        return redirect(
            url_for("main.dashboard")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        # ----------------------------------------------------
        # Find user
        # ----------------------------------------------------

        user = User.query.filter_by(
            email=email
        ).first()

        # ----------------------------------------------------
        # Unlock expired account lock
        # ----------------------------------------------------

        if user is not None:

            SecurityService.unlock_if_expired(
                user
            )

        # ----------------------------------------------------
        # Build ML features
        # ----------------------------------------------------

        features, indicators = (
            _build_auth_features(user)
        )

        # ----------------------------------------------------
        # IDS prediction
        # ----------------------------------------------------

        predictor = IntrusionPredictor(
            current_app.config["MODEL_PATH"]
        )

        risk_score = predictor.predict_risk(
            features
        )

        # ----------------------------------------------------
        # Validate credentials
        # ----------------------------------------------------

        success = bool(
            user
            and user.check_password(password)
            and user.is_active
        )

        # ----------------------------------------------------
        # Store authentication telemetry
        # ----------------------------------------------------

        login_log = LoginLog(

            user_id=(
                user.id
                if user
                else None
            ),

            email=email or "unknown",

            ip_address=_client_ip(),

            user_agent=request.headers.get(
                "User-Agent",
                "",
            )[:512],

            country_code=request.headers.get(
                "X-Country-Code",
                "UNK",
            )[:8],

            success=success,

            risk_score=risk_score,

            suspicious_indicators=";".join(
                indicators
            ),
        )

        db.session.add(login_log)

        db.session.flush()

        security_event = SecurityService.analyze_authentication(
            login_log_id=login_log.id,
            user_id=user.id if user else None,
            success=success,
            ml_risk_score=risk_score,
            indicators=indicators,
        )

        # ----------------------------------------------------
        # Successful authentication
        # ----------------------------------------------------

        if success:

            SecurityService.register_successful_login(
                user
            )

            SecurityService.audit(
                user.id,
                "LOGIN_SUCCESS",
                "User",
                str(user.id),
                f"Risk score {risk_score:.3f}.",
            )

            db.session.commit()

            session.permanent = True

            login_user(user)

            return redirect(
                url_for("main.dashboard")
            )

        # ----------------------------------------------------
        # Failed authentication
        # ----------------------------------------------------

        SecurityService.register_failed_login(
            user,
            email,
            risk_score,
            login_log.id,
        )

        db.session.commit()

        flash(
            "Invalid credentials or account unavailable."
        )

        return (
            render_template_string(
                LOGIN_TEMPLATE,
                style=AUTH_STYLE,
            ),
            401,
        )

    return render_template_string(
        LOGIN_TEMPLATE,
        style=AUTH_STYLE,
    )


# ============================================================
# FORGOT PASSWORD
# ============================================================

@auth_bp.route(
    "/forgot-password",
    methods=["GET", "POST"],
)
def forgot_password():

    if current_user.is_authenticated:

        return redirect(
            url_for("main.dashboard")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        # ----------------------------------------------------
        # Always use generic response
        # ----------------------------------------------------

        generic_message = (
            "If an account exists for that email, "
            "a password-reset link has been sent."
        )

        # ----------------------------------------------------
        # Validate email format
        # ----------------------------------------------------

        if not _valid_email(email):

            flash(generic_message)

            return render_template_string(
                FORGOT_PASSWORD_TEMPLATE,
                style=AUTH_STYLE,
            )

        # ----------------------------------------------------
        # Find account
        # ----------------------------------------------------

        user = User.query.filter_by(
            email=email
        ).first()

        if user is not None:

            # ------------------------------------------------
            # Generate secure reset token
            # ------------------------------------------------

            token = _generate_reset_token(
                user
            )

            reset_link = _build_reset_url(token)

            # ------------------------------------------------
            # Audit reset request
            # ------------------------------------------------

            SecurityService.audit(
                user.id,
                "PASSWORD_RESET_REQUEST",
                "User",
                str(user.id),
                "Password recovery requested.",
            )

            db.session.commit()

            # ------------------------------------------------
            # Attempt email delivery
            # ------------------------------------------------

            if reset_link is not None:
                _send_password_reset_email(user, reset_link)
            else:
                current_app.logger.warning(
                    "Password reset mail status=%s reason=APP_BASE_URL_INVALID_OR_MISSING",
                    MAIL_CONFIGURATION_MISSING,
                )
        else:
            # Preserve the indistinguishable browser response while making the
            # deliberate no-send branch visible to a local operator.
            current_app.logger.info("Password reset request processed: no matching account; SMTP not attempted.")

        flash(generic_message)

    return render_template_string(
        FORGOT_PASSWORD_TEMPLATE,
        style=AUTH_STYLE,
    )


# ============================================================
# RESET PASSWORD
# ============================================================

@auth_bp.route(
    "/reset-password/<token>",
    methods=["GET", "POST"],
)
def reset_password(token):

    # --------------------------------------------------------
    # Validate token
    # --------------------------------------------------------

    user = _load_user_from_reset_token(
        token
    )

    if user is None:

        flash(
            "This password reset link is invalid or has expired."
        )

        return redirect(
            url_for("auth.forgot_password")
        )

    # --------------------------------------------------------
    # Process password update
    # --------------------------------------------------------

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # ----------------------------------------------------
        # Password strength
        # ----------------------------------------------------

        if not PASSWORD_RE.match(password):

            flash(
                "Password must be 12-128 characters "
                "with uppercase, lowercase, number, and symbol."
            )

            return render_template_string(
                RESET_PASSWORD_TEMPLATE,
                style=AUTH_STYLE,
            ), 400

        # ----------------------------------------------------
        # Confirm password
        # ----------------------------------------------------

        if password != confirm_password:

            flash(
                "Passwords do not match."
            )

            return render_template_string(
                RESET_PASSWORD_TEMPLATE,
                style=AUTH_STYLE,
            ), 400

        # ----------------------------------------------------
        # Prevent same password
        # ----------------------------------------------------

        if user.check_password(password):

            flash(
                "New password must be different from your current password."
            )

            return render_template_string(
                RESET_PASSWORD_TEMPLATE,
                style=AUTH_STYLE,
            ), 400

        # ----------------------------------------------------
        # Update password
        # ----------------------------------------------------

        user.set_password(password)
        reset_record = _load_reset_record(token)
        if reset_record is None:
            flash("This password reset link is invalid or has expired.")
            return redirect(url_for("auth.forgot_password"))
        reset_record.used_at = datetime.now(timezone.utc).replace(tzinfo=None)

        # ----------------------------------------------------
        # Reset failed-login state if the model provides it
        # ----------------------------------------------------

        if hasattr(user, "failed_login_count"):

            user.failed_login_count = 0

        # ----------------------------------------------------
        # Audit password change
        # ----------------------------------------------------

        SecurityService.audit(
            user.id,
            "PASSWORD_RESET",
            "User",
            str(user.id),
            "Password successfully reset using recovery token.",
        )

        db.session.commit()

        # ----------------------------------------------------
        # Password reset successful
        # ----------------------------------------------------

        flash(
            "Password reset successful. You can now sign in."
        )

        return redirect(
            url_for("auth.login")
        )

    return render_template_string(
        RESET_PASSWORD_TEMPLATE,
        style=AUTH_STYLE,
    )


# ============================================================
# LOGOUT
# ============================================================

@auth_bp.route(
    "/logout",
    methods=["POST", "GET"],
)
def logout():

    if current_user.is_authenticated:

        SecurityService.audit(
            current_user.id,
            "LOGOUT",
            "User",
            str(current_user.id),
            "User ended session.",
        )

        db.session.commit()

        logout_user()

    return redirect(
        url_for("auth.login")
    )


# ============================================================
# PASSWORD RESET TOKEN GENERATION
# ============================================================

def _generate_reset_token(
    user: User,
) -> str:
    raw_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).update(
        {PasswordResetToken.used_at: now}, synchronize_session=False
    )
    db.session.add(PasswordResetToken(
        user_id=user.id,
        token_hash=_hash_reset_token(raw_token),
        expires_at=now + timedelta(minutes=current_app.config["PASSWORD_RESET_MINUTES"]),
    ))
    return raw_token


def _load_user_from_reset_token(
    token: str,
):
    record = _load_reset_record(token)
    return record.user if record and record.user.is_active else None


def _load_reset_record(token: str) -> PasswordResetToken | None:
    if not token or len(token) > 256:
        return None
    record = PasswordResetToken.query.filter_by(token_hash=_hash_reset_token(token)).first()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if record is None or record.used_at is not None or record.expires_at <= now:
        return None
    return record


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _build_reset_url(token: str) -> str | None:
    """Build the reset path with Flask routing and a configured public origin."""
    base_url = current_app.config.get("APP_BASE_URL", "").strip()
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    reset_path = url_for("auth.reset_password", token=token, _external=False)
    return urljoin(f"{base_url.rstrip('/')}/", reset_path.lstrip("/"))


# ============================================================
# EMAIL DELIVERY
# ============================================================

def _send_password_reset_email(
    user: User,
    reset_link: str,
) -> str:

    smtp_host = current_app.config.get("MAIL_SERVER")

    smtp_port = current_app.config.get(
        "MAIL_PORT",
        587,
    )

    smtp_username = current_app.config.get(
        "MAIL_USERNAME"
    )

    smtp_password = current_app.config.get(
        "MAIL_PASSWORD"
    )

    smtp_sender = current_app.config.get("MAIL_DEFAULT_SENDER") or smtp_username

    smtp_use_tls = current_app.config.get(
        "MAIL_USE_TLS",
        True,
    )

    # --------------------------------------------------------
    # SMTP not configured
    # --------------------------------------------------------

    recipient_domain = user.email.rsplit("@", 1)[-1].lower() if "@" in user.email else "invalid"

    def log_status(status: str, level: str = "info") -> str:
        getattr(current_app.logger, level)(
            "Password reset mail status=%s host=%s port=%s sender=%s recipient_domain=%s tls=%s",
            status, smtp_host, smtp_port, smtp_sender, recipient_domain, bool(smtp_use_tls),
        )
        return status

    if not all([smtp_host, smtp_username, smtp_password, smtp_sender]):
        return log_status(MAIL_CONFIGURATION_MISSING, "warning")

    message = EmailMessage()

    message["Subject"] = "SOC Command Center - Password Reset"

    message["From"] = smtp_sender

    message["To"] = user.email

    message.set_content(
        f"""
Security Operations Center

A password reset was requested for your analyst account.

Use the following link to create a new password:

{reset_link}

This link expires in {current_app.config['PASSWORD_RESET_MINUTES']} minutes.

If you did not request this password reset,
you can safely ignore this email.

AI-Powered Authentication & Intrusion Detection System
""".strip()
    )
    try:
        with smtplib.SMTP(
            smtp_host,
            smtp_port,
            timeout=10,
        ) as server:
            server.ehlo()
            if smtp_use_tls:
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            current_app.logger.info(
                "Password reset mail SMTP connection established host=%s port=%s tls=%s",
                smtp_host, smtp_port, bool(smtp_use_tls),
            )
            try:
                server.login(smtp_username, smtp_password)
            except smtplib.SMTPAuthenticationError:
                if current_app.debug:
                    current_app.logger.exception("Password reset mail SMTP authentication failure.")
                return log_status(SMTP_AUTH_FAILED, "warning")
            try:
                server.send_message(message)
            except smtplib.SMTPRecipientsRefused:
                return log_status(SMTP_RECIPIENT_REJECTED, "warning")
            except (ValueError, smtplib.SMTPException):
                return log_status(SMTP_SEND_FAILED, "warning")
        return log_status(EMAIL_SENT)
    except (OSError, smtplib.SMTPConnectError):
        return log_status(SMTP_CONNECTION_FAILED, "warning")
    except (ValueError, smtplib.SMTPException):
        if current_app.debug:
            current_app.logger.exception("Password reset mail SMTP failure (safe traceback; message body omitted).")
        return log_status(SMTP_SEND_FAILED, "warning")


# ============================================================
# EMAIL VALIDATION
# ============================================================

def _valid_email(
    email: str,
) -> bool:

    return bool(
        EMAIL_RE.match(email)
    )


# ============================================================
# CLIENT IP
# ============================================================

def _client_ip() -> str:

    forwarded_for = request.headers.get(
        "X-Forwarded-For",
        "",
    )

    if forwarded_for:

        return forwarded_for.split(
            ",",
            1,
        )[0].strip()

    return (
        request.remote_addr
        or "0.0.0.0"
    )


# ============================================================
# AUTHENTICATION FEATURES
# ============================================================

def _build_auth_features(
    user: User | None,
) -> tuple[list[float], list[str]]:

    indicators: list[str] = []

    now = datetime.now(
        timezone.utc
    )

    # --------------------------------------------------------
    # IP analysis
    # --------------------------------------------------------

    ip_address = _client_ip()

    suspicious_ip = _is_suspicious_ip(
        ip_address
    )

    if suspicious_ip:

        indicators.append(
            "suspicious_ip_space"
        )

    # --------------------------------------------------------
    # Country mismatch
    # --------------------------------------------------------

    country_code = request.headers.get(
        "X-Country-Code",
        "UNK",
    ).upper()

    expected_country = request.headers.get(
        "X-Expected-Country",
        country_code,
    ).upper()

    country_mismatch = (
        country_code != expected_country
    )

    if country_mismatch:

        indicators.append(
            "country_mismatch"
        )

    # --------------------------------------------------------
    # Previous failed attempts
    # --------------------------------------------------------

    preceding_fails = (
        user.failed_login_count
        if user
        else 0
    )

    if preceding_fails:

        indicators.append(
            f"preceding_failures:{preceding_fails}"
        )

    # Repeated authentication behavior is derived from prior telemetry rather
    # than supplied by a form. It is an explainability indicator; the existing
    # trained model still receives only its documented five features.
    recent_attempts = LoginLog.query.filter(
        LoginLog.email == (user.email if user else request.form.get("email", "").strip().lower()),
        LoginLog.created_at >= (now - timedelta(minutes=5)).replace(tzinfo=None),
    ).count()
    if recent_attempts >= 4:
        indicators.append(f"authentication_burst:{recent_attempts}")

    # --------------------------------------------------------
    # Device recognition
    # --------------------------------------------------------

    user_agent = request.headers.get("User-Agent", "")[:512]
    known_device = bool(user and LoginLog.query.filter_by(
        user_id=user.id, user_agent=user_agent, success=True
    ).first())
    new_device = 1 if "X-Known-Device" not in request.headers and not known_device else 0

    if new_device:

        indicators.append(
            "unrecognized_device"
        )

    # --------------------------------------------------------
    # ML feature vector
    # --------------------------------------------------------

    features = [

        float(now.hour),

        float(preceding_fails),

        float(suspicious_ip),

        float(country_mismatch),

        float(new_device),

    ]

    return features, indicators


# ============================================================
# SUSPICIOUS IP DETECTION
# ============================================================

def _is_suspicious_ip(
    ip_address: str,
) -> bool:

    try:

        parsed = ipaddress.ip_address(
            ip_address
        )

    except ValueError:

        return True

    return bool(
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_reserved
        or parsed.is_multicast
    )
