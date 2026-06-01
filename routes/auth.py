import ipaddress
import re
from datetime import datetime, timezone

from flask import Blueprint, current_app, flash, redirect, render_template_string, request, session, url_for
from flask_login import current_user, login_user, logout_user

from app import db, limiter
from ml.predict import IntrusionPredictor
from models.log import LoginLog
from models.user import Role, User
from services.security_service import SecurityService


auth_bp = Blueprint("auth", __name__)
PASSWORD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,128}$")

REGISTER_TEMPLATE = """
<h1>Register</h1>
{% with messages = get_flashed_messages() %}{% for message in messages %}<p>{{ message }}</p>{% endfor %}{% endwith %}
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="email" type="email" required>
  <input name="password" type="password" required>
  <button type="submit">Register</button>
</form>
"""

LOGIN_TEMPLATE = """
<h1>Login</h1>
{% with messages = get_flashed_messages() %}{% for message in messages %}<p>{{ message }}</p>{% endfor %}{% endwith %}
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="email" type="email" required>
  <input name="password" type="password" required>
  <button type="submit">Login</button>
</form>
"""


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not _valid_email(email):
            flash("A valid email address is required.")
            return render_template_string(REGISTER_TEMPLATE), 400
        if not PASSWORD_RE.match(password):
            flash("Password must be 12-128 characters with uppercase, lowercase, number, and symbol.")
            return render_template_string(REGISTER_TEMPLATE), 400
        if User.query.filter_by(email=email).first() is not None:
            flash("Account already exists.")
            return render_template_string(REGISTER_TEMPLATE), 409

        role = Role.query.filter_by(name="analyst").first()
        if role is None:
            role = Role(name="analyst", description="Standard telemetry analyst")
            db.session.add(role)
            db.session.flush()
        user = User(email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        SecurityService.audit(user.id, "REGISTER", "User", str(user.id), "Self-service account registration.")
        db.session.commit()
        session.permanent = True
        login_user(user)
        return redirect(url_for("main.dashboard"))
    return render_template_string(REGISTER_TEMPLATE)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"], methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user is not None:
            SecurityService.unlock_if_expired(user)

        features, indicators = _build_auth_features(user)
        predictor = IntrusionPredictor(current_app.config["MODEL_PATH"])
        risk_score = predictor.predict_risk(features)
        success = bool(user and user.check_password(password) and user.is_active)

        login_log = LoginLog(
            user_id=user.id if user else None,
            email=email or "unknown",
            ip_address=_client_ip(),
            user_agent=request.headers.get("User-Agent", "")[:512],
            country_code=request.headers.get("X-Country-Code", "UNK")[:8],
            success=success,
            risk_score=risk_score,
            suspicious_indicators=";".join(indicators),
        )
        db.session.add(login_log)
        db.session.flush()

        if success:
            SecurityService.register_successful_login(user)
            SecurityService.audit(user.id, "LOGIN_SUCCESS", "User", str(user.id), f"Risk score {risk_score:.3f}.")
            db.session.commit()
            session.permanent = True
            login_user(user)
            return redirect(url_for("main.dashboard"))

        SecurityService.register_failed_login(user, email, risk_score, login_log.id)
        db.session.commit()
        flash("Invalid credentials or account unavailable.")
        return render_template_string(LOGIN_TEMPLATE), 401
    return render_template_string(LOGIN_TEMPLATE)


@auth_bp.route("/logout", methods=["POST", "GET"])
def logout():
    if current_user.is_authenticated:
        SecurityService.audit(current_user.id, "LOGOUT", "User", str(current_user.id), "User ended session.")
        db.session.commit()
        logout_user()
    return redirect(url_for("auth.login"))


def _valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def _client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr or "0.0.0.0"


def _build_auth_features(user: User | None) -> tuple[list[float], list[str]]:
    indicators: list[str] = []
    now = datetime.now(timezone.utc)
    ip_address = _client_ip()
    suspicious_ip = _is_suspicious_ip(ip_address)
    if suspicious_ip:
        indicators.append("suspicious_ip_space")
    country_code = request.headers.get("X-Country-Code", "UNK").upper()
    expected_country = request.headers.get("X-Expected-Country", country_code).upper()
    country_mismatch = country_code != expected_country
    if country_mismatch:
        indicators.append("country_mismatch")
    preceding_fails = user.failed_login_count if user else 0
    if preceding_fails:
        indicators.append(f"preceding_failures:{preceding_fails}")
    new_device = 1 if "X-Known-Device" not in request.headers else 0
    if new_device:
        indicators.append("unrecognized_device")
    return [float(now.hour), float(preceding_fails), float(suspicious_ip), float(country_mismatch), float(new_device)], indicators


def _is_suspicious_ip(ip_address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return True
    return bool(parsed.is_private or parsed.is_loopback or parsed.is_reserved or parsed.is_multicast)
