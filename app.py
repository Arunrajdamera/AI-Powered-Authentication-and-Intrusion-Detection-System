import logging
from logging.handlers import RotatingFileHandler

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

from config import Config


db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)


def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    for folder_key in ("DATABASE_DIR", "LOG_DIR", "REPORT_DIR", "ML_DIR"):
        app.config[folder_key].mkdir(parents=True, exist_ok=True)

    _configure_logging(app)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"

    from models.user import User

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:
        if not user_id.isdigit():
            return None
        return db.session.get(User, int(user_id))

    from routes.admin import admin_bp
    from routes.auth import auth_bp
    from routes.main import main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")

    return app


def _configure_logging(app: Flask) -> None:
    log_path = app.config["LOG_DIR"] / "app.log"
    handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=5)
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )
    for existing_handler in list(app.logger.handlers):
        app.logger.removeHandler(existing_handler)
        existing_handler.close()
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
