"""Изолированный прогон пары 6: Core NATS, Keycloak и HTTP-страницы SOC."""
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import threading
import time
from tempfile import TemporaryDirectory

import requests
from flask_wtf.csrf import generate_csrf
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from app import create_app
from app.passport import KeycloakPoller
from citykit import create_city_app, make_event, topic_for

def wait_for(probe):
    for _ in range(120):
        try:
            value = probe()
            if value:
                return value
        except requests.ConnectionError:
            pass
        time.sleep(1)
    raise RuntimeError("Истекло время ожидания стенда")

def session_user(client, name, roles):
    with client.session_transaction() as session:
        session["user"] = {"username": name, "name": name, "sub": name, "roles": roles}

with TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    realm = {"realm": "lab", "enabled": True, "eventsEnabled": True,
             "clients": [{"clientId": "district", "enabled": True, "publicClient": True,
                          "directAccessGrantsEnabled": True}]}
    config = tmp / "lab-realm.json"
    config.write_text(json.dumps(realm))
    admin_pass = secrets.token_urlsafe(32)
    env = dict(os.environ, KC_BOOTSTRAP_ADMIN_USERNAME="lab-admin", KC_BOOTSTRAP_ADMIN_PASSWORD=admin_pass)
    subprocess.run(["docker", "run", "-d", "--rm", "--name", "pair6-keycloak", "-p", "127.0.0.1:18080:8080",
                    "-e", "KC_BOOTSTRAP_ADMIN_USERNAME", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD",
                    "-v", f"{config}:/opt/keycloak/data/import/lab-realm.json:ro",
                    "quay.io/keycloak/keycloak:26.0", "start-dev", "--import-realm"], check=True, env=env)
    kc = "http://127.0.0.1:18080"
    wait_for(lambda: requests.get(kc + "/realms/lab/.well-known/openid-configuration", timeout=4).ok)
    cfg = {"SECRET_KEY": secrets.token_hex(32), "DATABASE": str(tmp/"soc.db"), "NATS_URL": "nats://127.0.0.1:4222"}
    soc = create_app(cfg)
    bus = soc.extensions["city"]["bus"]
    seen = []
    bus.subscribe("city.events.soc.alert.*.v1", lambda topic, event: seen.append((topic, event)))
    wait_for(lambda: bus._nc and bus._nc.is_connected)
    bus.flush()
    for district in ("bank", "cityhall", "grid", "hospital"):
        district_app = create_city_app(__name__, district, district, [], "", {
            **cfg, "DATABASE": str(tmp / (district+".db")), "BUS": bus})
        district_app.add_url_rule("/session-form", view_func=generate_csrf, endpoint="session_form")
        client = district_app.test_client()
        session_user(client, "lab-resident", ["житель"])
        csrf = client.get("/session-form").text
        assert client.post("/auth/logout", data={"csrf_token": csrf}).status_code == 302

    event = make_event("grid", "web", "city.grid.alarm.raised.v1", "meter/demo", {"meter": "demo"})
    for _ in range(2):
        bus.publish(topic_for(event["type"]), event)
    wait_for(lambda: len(seen) >= 1)

    token_url = kc+"/realms/{}/protocol/openid-connect/token"
    auth = requests.post(token_url.format("master"), data={"client_id":"admin-cli", "grant_type":"password",
                        "username":"lab-admin", "password":admin_pass}, timeout=10)
    auth.raise_for_status()
    poller = KeycloakPoller(kc+"/realms/lab", "", "", on_record=lambda rec: bus.publish("city.logs.passport", rec))
    for _ in range(3):
        result = requests.post(token_url.format("lab"), data={"client_id":"district","grant_type":"password",
                               "username":"lab-resident","password":"invalid-demo-input"}, timeout=10)
        assert result.status_code in (400, 401) and result.json().get("error") == "invalid_grant"
    records = requests.get(kc+"/admin/realms/lab/events", params={"type":"LOGIN_ERROR"},
                           headers={"Authorization":"Bearer "+auth.json()["access_token"]}, timeout=10)
    records.raise_for_status()
    assert poller.process(records.json()) == 3
    wait_for(lambda: any(e["data"].get("rule")=="brute_force" for _,e in seen))
    db = sqlite3.connect(cfg["DATABASE"])
    wait_for(lambda: db.execute("SELECT COUNT(DISTINCT district) FROM logs").fetchone()[0] == 6)
    server = make_server("127.0.0.1", 0, soc)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    client = soc.test_client()
    session_user(client, "lab-analyst", ["аналитик_soc"])
    cookie_name = soc.config["SESSION_COOKIE_NAME"]
    with sync_playwright() as playwright:
        chrome = playwright.chromium.launch(channel="chrome", args=["--no-sandbox"])
        page = chrome.new_page(viewport={"width":1600,"height":1000}, locale="ru-RU")
        page.context.add_cookies([{"name":cookie_name, "value":client.get_cookie(cookie_name).value, "url":base}])
        for url, name in [("/panel","01-stream"),("/panel?district=passport&event=auth.login.failure","02-filter"),("/","03-brute-force")]:
            assert page.goto(base+url).status == 200
            if name=="02-filter":
                assert page.locator("table tr").count()==4
            if name=="03-brute-force":
                assert page.get_by_text("Перебор паролей",exact=False).count()==1
            page.screenshot(path=f"submission/{name}.png",full_page=True)
        page.locator("tr").filter(has_text="Перебор паролей").get_by_role("button").click()
        wait_for(lambda: any(topic=="city.events.soc.alert.closed.v1" for topic,_ in seen))
        chrome.close()
    server.shutdown()
