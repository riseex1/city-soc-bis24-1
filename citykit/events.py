"""События города в общем «конверте» (соглашение Р5, по образцу CloudEvents 1.0)."""

import re
import uuid

from .logs import now_iso

TYPE_RE = re.compile(r"^city\.[a-z]+\.[a-z_]+\.[a-z_]+\.v\d+$")


def make_event(district: str, service: str, etype: str, subject: str, data: dict) -> dict:
    """Собрать событие. В subject и data — только идентификаторы, без ФИО и диагнозов."""
    if not TYPE_RE.match(etype):
        raise ValueError(f"тип события не по Р5: {etype}")
    return {
        "specversion": "1.0",
        "id": str(uuid.uuid4()),
        "source": f"/{district}/{service}",
        "type": etype,
        "time": now_iso(),
        "subject": subject,
        "datacontenttype": "application/json",
        "data": data,
    }


def topic_for(etype: str) -> str:
    """city.bank.fee.paid.v1 → тема NATS city.events.bank.fee.paid.v1"""
    return "city.events." + etype.removeprefix("city.")


def valid_event(e: dict) -> bool:
    """Проверка входящего события: все поля конверта на месте и тип по Р5."""
    need = ("specversion", "id", "source", "type", "time", "data")
    return all(k in e for k in need) and isinstance(e["data"], dict) and bool(TYPE_RE.match(str(e["type"])))
