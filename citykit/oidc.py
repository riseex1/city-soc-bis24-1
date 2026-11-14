"""Вход через Паспортный стол (Keycloak, OpenID Connect) и проверка ролей."""

import functools
from urllib.parse import urlencode

from flask import Blueprint, abort, current_app, redirect, render_template, request, session, url_for

bp = Blueprint("oidc", __name__, url_prefix="/auth")


def init_app(app) -> None:
    app.register_blueprint(bp)
    issuer = app.config.get("OIDC_ISSUER")
    if not issuer:
        return  # тесты: вход подменяется записью в сессию
    from authlib.integrations.flask_client import OAuth

    oauth = OAuth(app)
    oauth.register(
        name="city",
        client_id=app.config["OIDC_CLIENT_ID"],
        client_secret=app.config["OIDC_CLIENT_SECRET"],
        server_metadata_url=f"{issuer}/.well-known/openid-configuration",
        # PKCE (S256): перехваченный код авторизации бесполезен без секрета из этой сессии
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
    )
    app.extensions["city_oauth"] = oauth


def current_user() -> dict | None:
    return session.get("user")


def has_role(*roles: str) -> bool:
    user = current_user()
    return bool(user) and bool(set(user.get("roles", [])) & set(roles))


def login_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if current_user() is None:
            return redirect(url_for("oidc.login", next=request.path))
        return view(**kwargs)

    return wrapped


def role_required(*roles: str):
    """ИБ: роль проверяется на сервере при каждом запросе. Спрятанная кнопка — не защита."""

    def deco(view):
        @functools.wraps(view)
        @login_required
        def wrapped(**kwargs):
            if not has_role(*roles):
                current_app.extensions["city"]["log"](
                    "WARN",
                    "access.denied",
                    "failure",
                    "нет нужной роли",
                    details={"path": request.path[:200], "need": list(roles)},
                )
                abort(403)
            return view(**kwargs)

        return wrapped

    return deco


def _safe_next(nxt: str | None) -> str:
    # ИБ: возвращаемся только на свои страницы (защита от открытого перенаправления).
    if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
        return "/"
    return nxt


@bp.route("/login")
def login():
    oauth = current_app.extensions.get("city_oauth")
    if oauth is None:
        abort(503, "Вход не настроен: нет OIDC_ISSUER.")
    session["next"] = _safe_next(request.args.get("next"))
    try:
        return oauth.city.authorize_redirect(current_app.config["PUBLIC_URL"] + "/auth/callback")
    except Exception as exc:  # noqa: BLE001 — Keycloak ещё не запущен или недоступен
        current_app.extensions["city"]["log"](
            "ERROR", "service.error", "failure", "Паспортный стол недоступен", details={"error": type(exc).__name__}
        )
        text = "Паспортный стол (вход в город) недоступен. Проверьте, что ядро города запущено, и подождите минуту."
        return render_template("city_error.html", code=503, text=text), 503


@bp.route("/callback")
def callback():
    log = current_app.extensions["city"]["log"]
    oauth = current_app.extensions.get("city_oauth")
    if oauth is None:
        abort(503)
    try:
        # Authlib проверяет state, обменивает код на токены и проверяет подпись ID-токена.
        token = oauth.city.authorize_access_token()
    except Exception as exc:  # noqa: BLE001 — любой сбой входа пишем в журнал одинаково
        log("WARN", "auth.login.failure", "failure", "вход не удался", details={"error": type(exc).__name__})
        return render_template("city_error.html", code=400, text="Вход не удался. Попробуйте ещё раз."), 400
    info = token.get("userinfo") or {}
    nxt = session.pop("next", "/")
    session.clear()  # ИБ: новая сессия после входа
    session["user"] = {
        "sub": info.get("sub"),
        "username": info.get("preferred_username", info.get("sub")),
        "name": info.get("name") or info.get("preferred_username", ""),
        "roles": sorted(info.get("roles", [])),
    }
    session["id_token"] = token.get("id_token", "")
    log("INFO", "auth.login.success", "success", "вход через Паспортный стол")
    return redirect(_safe_next(nxt))


@bp.route("/logout", methods=("POST",))
def logout():
    log = current_app.extensions["city"]["log"]
    if current_user():
        log("INFO", "auth.logout.success", "success", "выход")
    id_token = session.get("id_token", "")
    session.clear()
    oauth = current_app.extensions.get("city_oauth")
    if oauth is None:
        return redirect("/")
    # Выход и из Паспортного стола, иначе следующий «Войти» пустит без пароля.
    try:
        end = oauth.city.load_server_metadata().get("end_session_endpoint")
    except Exception:  # noqa: BLE001 — Паспортный стол недоступен: выходим только из района
        end = None
    params = {
        "client_id": current_app.config["OIDC_CLIENT_ID"],
        "post_logout_redirect_uri": current_app.config["PUBLIC_URL"] + "/",
    }
    if id_token:
        params["id_token_hint"] = id_token
    return redirect(f"{end}?{urlencode(params)}" if end else "/")
