"""citykit — общий код районов «Цифрового города» (группа 2).

Не меняйте его в своём районе: исправления делаются в общей версии и раздаются всем.
"""

from .db import get_db
from .events import make_event, topic_for, valid_event
from .oidc import current_user, has_role, login_required, role_required
from .web import create_city_app

__all__ = [
    "create_city_app",
    "current_user",
    "get_db",
    "has_role",
    "log",
    "login_required",
    "make_event",
    "publish_event",
    "role_required",
    "topic_for",
    "valid_event",
]


def log(level: str, event: str, outcome: str, msg: str, **fields) -> dict:
    """Запись в журнал района (stdout + Транспорт). Вызывать внутри приложения."""
    from flask import current_app

    return current_app.extensions["city"]["log"](level, event, outcome, msg, **fields)


def publish_event(etype: str, subject: str, data: dict) -> dict:
    """Отправить событие города в Транспорт и отметить это в журнале."""
    from flask import current_app

    city = current_app.extensions["city"]
    event = make_event(city["district"], "web", etype, subject, data)
    city["bus"].publish(topic_for(etype), event)
    log("INFO", "event.published", "success", f"событие {etype}", details={"event_id": event["id"]})
    return event
