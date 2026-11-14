"""Журнал по соглашению Р4: JSON Lines в stdout и копия в Транспорт (тема city.logs.<район>)."""

import json
import sys
import uuid
from datetime import UTC, datetime

LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")


def now_iso() -> str:
    """Время UTC с миллисекундами (Р3)."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class CityLog:
    def __init__(self, district: str, service: str, bus=None) -> None:
        self.district, self.service, self.bus = district, service, bus

    def __call__(self, level: str, event: str, outcome: str, msg: str, **fields) -> dict:
        assert level in LEVELS, level
        record = {
            "ts": now_iso(),
            "district": self.district,
            "service": self.service,
            "level": level,
            "event": event,
            "outcome": outcome,
            "msg": msg,
        }
        record.update(_request_fields())
        # Никаких паролей, токенов и диагнозов: только идентификаторы (Р4).
        record.update({k: v for k, v in fields.items() if v is not None})
        print(json.dumps(record, ensure_ascii=False), file=sys.stdout, flush=True)
        if self.bus is not None:
            self.bus.publish(f"city.logs.{self.district}", record)
        return record


def _request_fields() -> dict:
    """Кто и откуда — если запись сделана внутри HTTP-запроса."""
    try:
        from flask import g, has_request_context, request, session
    except ImportError:
        return {}
    if not has_request_context():
        return {}
    user = session.get("user")
    fwd = request.headers.get("X-Forwarded-For", "")
    return {
        "actor": f"user:{user['username']}" if user else "anonymous",
        "src_ip": fwd.split(",")[0].strip() or request.remote_addr,
        "request_id": getattr(g, "request_id", None) or uuid.uuid4().hex[:16],
    }
