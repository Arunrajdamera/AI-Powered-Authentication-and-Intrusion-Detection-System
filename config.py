import os
from pathlib import Path
from datetime import timedelta

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _database_uri() -> str:
    uri = os.getenv("SQLALCHEMY_DATABASE_URI")
    if not uri:
        return f"sqlite:///{BASE_DIR / 'database' / 'siem_ids.db'}"
    if uri.startswith("sqlite:///") and not Path(uri.removeprefix("sqlite:///")).is_absolute():
        return f"sqlite:///{BASE_DIR / uri.removeprefix('sqlite:///')}"
    return uri


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "development-only-change-me")
    SQLALCHEMY_DATABASE_URI = _database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = _bool_env("WTF_CSRF_ENABLED", True)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.getenv("SESSION_LIFETIME_MINUTES", "30")))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    LOGIN_RATE_LIMIT = os.getenv("LOGIN_RATE_LIMIT", "5 per minute")
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    FAILED_LOGIN_THRESHOLD = int(os.getenv("FAILED_LOGIN_THRESHOLD", "5"))
    ACCOUNT_LOCKOUT_MINUTES = int(os.getenv("ACCOUNT_LOCKOUT_MINUTES", "15"))
    HIGH_RISK_ALERT_THRESHOLD = float(os.getenv("HIGH_RISK_ALERT_THRESHOLD", "0.75"))
    MEDIUM_RISK_ALERT_THRESHOLD = float(os.getenv("MEDIUM_RISK_ALERT_THRESHOLD", "0.45"))
    DATABASE_DIR = BASE_DIR / "database"
    LOG_DIR = BASE_DIR / "logs"
    REPORT_DIR = BASE_DIR / "reports"
    ML_DIR = BASE_DIR / "ml"
    MODEL_PATH = ML_DIR / "random_forest_ids.joblib"
    METRICS_PATH = ML_DIR / "model_metrics.txt"


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    LOGIN_RATE_LIMIT = "1000 per minute"
    RATELIMIT_STORAGE_URI = "memory://"
