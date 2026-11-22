"""Проверки SOC: правила обнаружения, права, экранирование. Запуск: pytest"""

from citykit.logs import now_iso
from app.passport import KeycloakPoller, to_record
from conftest import csrf, login_as

from citykit import make_event, topic_for


def rec(event, actor="user:ivanov", ip="10.0.0.5", district="bank", msg="тест"):
    return {
        "ts": now_iso(),
        "district": district,
        "service": "web",
        "level": "WARN",
        "event": event,
        "outcome": "failure",
        "actor": actor,
        "src_ip": ip,
        "msg": msg,
    }


def alerts_html(client):
    login_as(client, "analyst", "аналитик_soc")
    return client.get("/").get_data(as_text=True)


def test_pages_need_analyst_role(client):
    login_as(client, "ivanov", "житель")
    assert client.get("/").status_code == 403
    assert client.get("/logs").status_code == 403


def test_brute_force_rule(client, bus):
    for _ in range(2):
        bus.publish("city.logs.passport", rec("auth.login.failure", district="passport"))
    assert "Перебор паролей" not in alerts_html(client).split("Правила:")[0]
    bus.publish("city.logs.passport", rec("auth.login.failure", district="passport"))
    html = alerts_html(client)
    assert "10.0.0.5" in html
    assert any(s == "city.events.soc.incident.opened.v1" for s, _ in bus.published)


def test_access_denied_rule_and_dedup(client, bus):
    for _ in range(6):
        bus.publish("city.logs.bank", rec("access.denied", actor="user:petrova"))
    login_as(client, "analyst", "аналитик_soc")
    assert client.get("/").get_data(as_text=True).count("<td>user:petrova</td>") <= 1
    incidents = [p for s, p in bus.published if s == "city.events.soc.incident.opened.v1"]
    assert len(incidents) == 1


def test_grid_alarm_creates_alert(client, bus):
    e = make_event(
        "grid", "web", "city.grid.alarm.raised.v1", "meter/m-north-1", {"meter": "m-north-1", "reason": "скачок"}
    )
    bus.publish(topic_for(e["type"]), e)
    bus.publish(topic_for(e["type"]), e)
    assert "m-north-1" in alerts_html(client)
    assert sum(topic == "city.events.soc.alert.raised.v1" for topic, _ in bus.published) == 1
    assert sum(p.get("event") == "foreign.event.handled" for _, p in bus.published) == 1


def test_log_message_is_escaped(client, bus):
    bus.publish("city.logs.cityhall", rec("data.change", msg="<script>alert(1)</script>"))
    login_as(client, "analyst", "аналитик_soc")
    html = client.get("/logs").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_log_filter_is_parameterized(client, bus):
    bus.publish("city.logs.bank", rec("data.change"))
    login_as(client, "analyst", "аналитик_soc")
    resp = client.get("/logs", query_string={"district": "bank' OR '1'='1"})
    assert resp.status_code == 200 and "data.change" not in resp.get_data(as_text=True)


def test_close_alert_needs_csrf(client, bus):
    e = make_event("grid", "web", "city.grid.alarm.raised.v1", "meter/x", {"meter": "x"})
    bus.publish(topic_for(e["type"]), e)
    login_as(client, "analyst", "аналитик_soc")
    assert client.post("/alerts/1/close").status_code == 400
    token = csrf(client, "/")
    client.post("/alerts/1/close", data={"csrf_token": token})
    client.post("/alerts/1/close", data={"csrf_token": token})
    assert sum(topic == "city.events.soc.alert.closed.v1" for topic, _ in bus.published) == 1
    assert "закрыта" in client.get("/").get_data(as_text=True)


def test_keycloak_events_converted():
    got = []
    p = KeycloakPoller("http://kc/realms/city", "soc", "s", on_record=got.append)
    p.last_ms = 0
    events = [
        {
            "time": 2,
            "type": "LOGIN_ERROR",
            "error": "invalid_user_credentials",
            "ipAddress": "1.2.3.4",
            "details": {"username": "ivanov"},
            "clientId": "bank",
        },
        {"time": 1, "type": "LOGIN", "ipAddress": "1.2.3.4", "details": {"username": "ivanov"}},
        {"time": 3, "type": "CODE_TO_TOKEN"},
    ]
    assert p.process(events) == 3
    assert [r["event"] for r in got] == ["auth.login.success", "auth.login.failure"]
    assert p.process(events) == 0  # повторно не берём
    assert to_record({"type": "LOGIN_ERROR", "time": 0})["actor"] == "user:unknown"
