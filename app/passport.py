"""События входа из Паспортного стола (Keycloak) → журнал SOC.

Keycloak не публикует журналы в Транспорт, поэтому SOC сам забирает события входа
через Admin REST API от имени своего служебного аккаунта (клиент soc, роль view-events).
"""

import threading
import time
from datetime import UTC, datetime

import requests

KINDS = {"LOGIN": ("auth.login.success", "success", "INFO"), "LOGIN_ERROR": ("auth.login.failure", "failure", "WARN")}


def to_record(ev: dict) -> dict | None:
    """Событие Keycloak → запись журнала по Р4."""
    kind = KINDS.get(ev.get("type"))
    if kind is None:
        return None
    event, outcome, level = kind
    details = ev.get("details") or {}
    username = details.get("username") or ev.get("userId") or "unknown"
    ts = datetime.fromtimestamp(ev.get("time", 0) / 1000, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {
        "ts": ts,
        "district": "passport",
        "service": "keycloak",
        "level": level,
        "event": event,
        "outcome": outcome,
        "actor": f"user:{username}",
        "src_ip": ev.get("ipAddress"),
        "msg": "вход в Паспортном столе" + ("" if outcome == "success" else f": {ev.get('error', 'ошибка')}"),
        "details": {"client": ev.get("clientId")},
    }


class KeycloakPoller(threading.Thread):
    def __init__(self, issuer: str, client_id: str, secret: str, on_record, interval: int = 15) -> None:
        super().__init__(name="keycloak-poller", daemon=True)
        self.issuer, self.client_id, self.secret = issuer, client_id, secret
        self.base = issuer.split("/realms/")[0]
        self.realm = issuer.rsplit("/", 1)[1]
        self.on_record, self.interval = on_record, interval
        self.last_ms = int(time.time() * 1000)  # старые события не тянем

    def token(self) -> str:
        r = requests.post(
            f"{self.issuer}/protocol/openid-connect/token",
            data={"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.secret},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()["access_token"]

    def fetch(self) -> list[dict]:
        r = requests.get(
            f"{self.base}/admin/realms/{self.realm}/events",
            params={"type": list(KINDS), "max": 200},
            headers={"Authorization": f"Bearer {self.token()}"},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()

    def process(self, events: list[dict]) -> int:
        new = sorted((e for e in events if e.get("time", 0) > self.last_ms), key=lambda e: e["time"])
        for ev in new:
            rec = to_record(ev)
            if rec:
                self.on_record(rec)
            self.last_ms = max(self.last_ms, ev["time"])
        return len(new)

    def run(self) -> None:
        while True:
            try:
                self.process(self.fetch())
            except (requests.RequestException, KeyError, ValueError):
                pass  # Паспортный стол ещё не запущен — попробуем позже
            time.sleep(self.interval)
