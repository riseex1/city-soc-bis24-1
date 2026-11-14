"""Общая сборка Flask-приложения района: настройки безопасности, журнал, шина, вход, база."""

import os
import uuid
from pathlib import Path

from flask import Blueprint, Flask, g, render_template, request
from flask_wtf.csrf import CSRFError, CSRFProtect
from jinja2 import ChoiceLoader, FileSystemLoader

from . import db, oidc
from .bus import MemoryBus, NatsBus
from .logs import CityLog

csrf = CSRFProtect()
KIT_DIR = Path(__file__).parent


def create_city_app(
    import_name: str,
    district: str,
    title: str,
    nav: list[tuple[str, str]],
    schema_sql: str,
    test_config: dict | None = None,
) -> Flask:
    app = Flask(import_name)
    data_dir = Path(os.environ.get("DATA_DIR", "data"))
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        DATABASE=str(data_dir / f"{district}.sqlite"),
        PUBLIC_URL=os.environ.get("PUBLIC_URL", f"http://{district}.city.localhost:8080").rstrip("/"),
        OIDC_ISSUER=os.environ.get("OIDC_ISSUER", "").rstrip("/"),
        OIDC_CLIENT_ID=os.environ.get("OIDC_CLIENT_ID", district),
        OIDC_CLIENT_SECRET=os.environ.get("OIDC_CLIENT_SECRET", ""),
        NATS_URL=os.environ.get("NATS_URL", ""),
        NATS_TOKEN=os.environ.get("NATS_TOKEN", ""),
        # ИБ: cookie сессии недоступна JavaScript и не уходит с чужих сайтов.
        SESSION_COOKIE_NAME=f"{district}_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        MAX_CONTENT_LENGTH=1024 * 1024,
        CITY_DISTRICT=district,
        CITY_TITLE=title,
        CITY_NAV=nav,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"] or app.config["SECRET_KEY"].startswith("замените"):
        raise RuntimeError("Нет SECRET_KEY: скопируйте .env.example в .env и задайте ключ (см. README).")
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    bus = app.config.get("BUS")
    if bus is None:
        url = app.config["NATS_URL"]
        bus = NatsBus(url, app.config["NATS_TOKEN"], f"{district}-web") if url else MemoryBus()
    log = CityLog(district, "web", bus)
    app.extensions["city"] = {"bus": bus, "log": log, "district": district}

    app.jinja_loader = ChoiceLoader(
        [FileSystemLoader(str(Path(app.root_path) / "templates")), FileSystemLoader(str(KIT_DIR / "templates"))]
    )
    app.register_blueprint(
        Blueprint("citykit", __name__, static_folder=str(KIT_DIR / "static"), static_url_path="/citykit-static")
    )
    csrf.init_app(app)
    oidc.init_app(app)
    app.teardown_appcontext(db.close_db)
    db.init_schema(app, schema_sql)

    @app.context_processor
    def city_globals():
        return {"current_user": oidc.current_user(), "has_role": oidc.has_role}

    @app.before_request
    def request_id():
        rid = request.headers.get("X-Request-ID", "")
        g.request_id = rid[:64] if rid else uuid.uuid4().hex[:16]

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers["X-Request-ID"] = getattr(g, "request_id", "")
        return resp

    @app.route("/health")
    def health():
        # /health не пишет в журнал: его часто опрашивают (Р6)
        return {"status": "ok"}

    @app.errorhandler(CSRFError)
    def csrf_error(err):
        log("WARN", "access.denied", "failure", "запрос без CSRF-токена", details={"path": request.path[:200]})
        return render_template("city_error.html", code=400, text="Форма устарела. Обновите страницу."), 400

    for code in (400, 403, 404, 413, 429, 503):
        app.register_error_handler(
            code,
            lambda err: (render_template("city_error.html", code=err.code, text=err.description), err.code),
        )
    return app
