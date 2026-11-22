"""Район «Городской SOC»: журналы всех районов, правила обнаружения, тревоги.

Откуда данные:
- журналы районов приходят через Транспорт (темы city.logs.<район>);
- события входа в Паспортном столе (Keycloak) SOC забирает сам, раз в 15 секунд (см. passport.py);
- тревоги Энергосети — событие city.grid.alarm.raised.v1.
"""

import json
import os
import sqlite3
import threading

from flask import abort, redirect, render_template, request, url_for

from citykit import create_city_app, current_user, get_db, log, make_event, publish_event, role_required, topic_for, valid_event

from .passport import KeycloakPoller

RULES = {
    "brute_force": "Перебор паролей: 3 и более неудачных входа с одного IP за 15 минут",
    "access_denied": "Попытки доступа к чужому: 3 и более отказа за 10 минут",
    "grid_alarm": "Тревога Энергосети: недостоверные показания или чужой счётчик",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    ts          TEXT, district TEXT, service TEXT, level TEXT, event TEXT, outcome TEXT,
    actor       TEXT, src_ip TEXT, request_id TEXT, msg TEXT, details TEXT
);
CREATE INDEX IF NOT EXISTS logs_event ON logs (event, received_at);
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rule       TEXT NOT NULL,
    key        TEXT NOT NULL,             -- кто: actor или IP
    district   TEXT,
    count      INTEGER NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE TABLE IF NOT EXISTS handled_grid_events (
    event_id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS reports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_sub    TEXT NOT NULL,
    category     TEXT NOT NULL CHECK (category IN ('suspicious_login', 'fraud', 'other')),
    summary      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'reviewed', 'dismissed')),
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    reviewer_sub TEXT,
    reviewed_at  TEXT
);
CREATE INDEX IF NOT EXISTS reports_owner ON reports (owner_sub, id);
"""

NAV = [("/", "Тревоги"), ("/panel", "Журналы"), ("/reports", "Мои сообщения"), ("/reports/queue", "Разбор сообщений")]
FIELDS = ("ts", "district", "service", "level", "event", "outcome", "actor", "src_ip", "request_id", "msg")
KEEP_LOGS = 20_000
REPORT_CATEGORIES = {
    "suspicious_login": "Подозрительный вход",
    "fraud": "Подозрение на мошенничество",
    "other": "Другое событие",
}
REPORT_STATUSES = {"new": "новое", "reviewed": "проверено", "dismissed": "не подтвердилось"}


def create_app(test_config: dict | None = None):
    app = create_city_app(__name__, "soc", "Городской SOC", NAV, SCHEMA, test_config)
    city = app.extensions["city"]
    def health_with_db():
        try:
            get_db().execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return {"status": "error", "database": "unavailable"}, 503

        return {"status": "ok", "database": "ok"}

    app.view_functions["health"] = health_with_db

    lock = threading.Lock()

    def connect():
        return sqlite3.connect(app.config["DATABASE"], timeout=10)

    def insert_alert(con, rule: str, key: str, district: str | None, count: int):
        # Одна тревога на правило и нарушителя за 10 минут — не засыпаем аналитика дублями.
        dup = con.execute(
            "SELECT 1 FROM alerts WHERE rule = ? AND key = ? AND created_at >= strftime('%Y-%m-%d %H:%M:%f', 'now', '-10 minutes')",
            (rule, key),
        ).fetchone()
        if dup:
            return
        cur = con.execute(
            "INSERT INTO alerts (rule, key, district, count) VALUES (?, ?, ?, ?)", (rule, key, district, count)
        )
        return cur.lastrowid, rule, district, count

    def publish_raised(alert):
        if alert is None:
            return
        alert_id, rule, district, count = alert
        subject = f"alert/{alert_id}"
        with app.app_context():
            publish_event("city.soc.alert.raised.v1", subject,
                          {"rule": rule, "district": district, "count": count})
            # Сохраняем существующую тему для подписчиков предыдущей версии.
            legacy = make_event("soc", "web", "city.soc.incident.opened.v1", subject,
                                {"alert_id": alert_id, "rule": rule, "district": district})
            city["bus"].publish(topic_for(legacy["type"]), legacy)

    def apply_rules(con, rec: dict):
        if rec.get("event") in ("login.failed", "auth.login.failure") and rec.get("src_ip"):
            n = con.execute(
                "SELECT COUNT(*) FROM logs WHERE event IN ('login.failed', 'auth.login.failure') "
                "AND src_ip = ? AND julianday(ts) BETWEEN julianday('now', '-15 minutes') AND julianday('now')",
                (rec["src_ip"],),
            ).fetchone()[0]
            if n >= 3:
                return insert_alert(con, "brute_force", rec["src_ip"], rec.get("district"), n)
        elif rec.get("event") == "access.denied" and rec.get("actor") not in (None, "anonymous"):
            n = con.execute(
                "SELECT COUNT(*) FROM logs WHERE event = 'access.denied' AND actor = ? "
                "AND received_at >= strftime('%Y-%m-%d %H:%M:%f', 'now', '-10 minutes')",
                (rec["actor"],),
            ).fetchone()[0]
            if n >= 3:
                return insert_alert(con, "access_denied", rec["actor"], rec.get("district"), n)

    def store_log(subject: str, rec: dict) -> None:
        """Запись журнала из Транспорта (другой поток)."""
        if not isinstance(rec.get("event"), str):
            return
        row = [str(rec.get(f))[:500] if rec.get(f) is not None else None for f in FIELDS]
        details = json.dumps(rec.get("details"), ensure_ascii=False)[:2000] if rec.get("details") else None
        with lock:
            con = connect()
            try:
                con.execute(
                    f"INSERT INTO logs ({', '.join(FIELDS)}, details) VALUES ({', '.join('?' * (len(FIELDS) + 1))})",
                    (*row, details),
                )
                con.execute("DELETE FROM logs WHERE id <= (SELECT MAX(id) FROM logs) - ?", (KEEP_LOGS,))
                alert = apply_rules(con, rec)
                con.commit()
            finally:
                con.close()

        publish_raised(alert)

    def on_grid_alarm(subject: str, event: dict) -> None:
        etype = "city.grid.alarm.raised.v1"
        if not valid_event(event) or event["type"] != etype or event["source"] != "/grid/web":
            return
        event_id = event["id"]
        if not isinstance(event_id, str) or not 0 < len(event_id) <= 128:
            return
        try:
            with lock:
                con = connect()
                try:
                    with con:
                        first = con.execute("INSERT OR IGNORE INTO handled_grid_events VALUES (?)", (event_id,)).rowcount
                        if not first:
                            return
                        meter = str(event["data"].get("meter", "?"))[:60]
                        alert = insert_alert(con, "grid_alarm", meter, "grid", 1)
                finally:
                    con.close()
        except sqlite3.Error:
            city["log"]("ERROR", "foreign.event.failed", "error", "ошибка обработки тревоги",
                        details={"event_id": event_id})
            raise
        publish_raised(alert)
        city["log"]("INFO", "foreign.event.handled", "success", "обработана тревога Энергосети",
                    details={"event_id": event_id, "from": "grid"})

    city["bus"].subscribe("city.logs.>", store_log)
    city["bus"].subscribe(topic_for("city.grid.alarm.raised.v1"), on_grid_alarm)

    issuer = app.config["OIDC_ISSUER"]
    if issuer and not app.config.get("TESTING"):
        KeycloakPoller(
            issuer,
            app.config["OIDC_CLIENT_ID"],
            app.config["OIDC_CLIENT_SECRET"],
            on_record=lambda rec: city["bus"].publish("city.logs.passport", rec),
            interval=int(os.environ.get("PASSPORT_POLL", "15")),
        ).start()
    app.extensions["soc_store_log"] = store_log  # для тестов

    @app.route("/")
    @role_required("аналитик_soc")
    def alerts():
        rows = get_db().execute("SELECT * FROM alerts ORDER BY status DESC, id DESC LIMIT 200").fetchall()
        return render_template("alerts.html", alerts=rows, rules=RULES)

    @app.route("/alerts/<int:alert_id>/close", methods=("POST",))
    @role_required("аналитик_soc")
    def close_alert(alert_id: int):
        db = get_db()
        changed = db.execute("UPDATE alerts SET status = 'closed' WHERE id = ? AND status = 'open'", (alert_id,)).rowcount
        db.commit()
        if not changed:
            if db.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
                abort(404)
            return redirect(url_for("alerts"))
        publish_event("city.soc.alert.closed.v1", f"alert/{alert_id}", {"status": "closed"})
        log("INFO", "data.change", "success", "тревога закрыта", details={"alert_id": alert_id})
        return redirect(url_for("alerts"))

    @app.route("/logs")
    @app.route("/panel")
    @role_required("аналитик_soc")
    def logs():
        where, args = [], []
        for col in ("district", "event", "level", "actor", "src_ip"):
            val = request.args.get(col, "").strip()
            if val:
                where.append(f"{col} = ?")  # имя колонки — из списка выше, значение — параметром
                args.append(val[:100])
        sql = "SELECT * FROM logs" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT 300"
        rows = get_db().execute(sql, args).fetchall()
        districts = [r[0] for r in get_db().execute("SELECT DISTINCT district FROM logs ORDER BY district")]
        count = get_db().execute("SELECT COUNT(*) FROM logs" + (" WHERE " + " AND ".join(where) if where else ""), args).fetchone()[0]
        opened = get_db().execute("SELECT COUNT(*) FROM alerts WHERE status = 'open'").fetchone()[0]
        return render_template("logs.html", rows=rows, districts=districts, args=request.args, count=count, opened=opened)

    @app.route("/reports", methods=("GET", "POST"))
    @role_required("житель")
    def reports():
        """Житель создаёт сообщение и видит только свои сообщения."""
        db = get_db()
        owner = current_user()["sub"]
        if request.method == "POST":
            # Белый список: принимаются только category и summary; owner_sub и status задаёт сервер.
            category = request.form.get("category", "")
            summary = request.form.get("summary", "").strip()
            if category not in REPORT_CATEGORIES or not 10 <= len(summary) <= 200:
                abort(400, "Выберите категорию и введите описание от 10 до 200 символов.")
            cur = db.execute(
                "INSERT INTO reports (owner_sub, category, summary) VALUES (?, ?, ?)",
                (owner, category, summary),
            )
            db.commit()
            # В журнале только факт: описание и прочие поля формы туда не попадают.
            log("INFO", "soc.report.created", "success", "сообщение жителя создано", details={"report_id": cur.lastrowid})
            return redirect(url_for("report_detail", report_id=cur.lastrowid))
        # Фильтр по статусу: значение только из белого списка, владелец в условии остаётся всегда.
        status = request.args.get("status", "").strip()
        if status and status not in REPORT_STATUSES:
            abort(400, "Недопустимый статус.")
        where = " AND status = ?" if status else ""
        rows = db.execute(
            "SELECT id, category, status, created_at FROM reports WHERE owner_sub = ?" + where + " ORDER BY id DESC",
            (owner, status) if status else (owner,),
        ).fetchall()
        return render_template(
            "reports.html",
            rows=rows,
            categories=REPORT_CATEGORIES,
            statuses=REPORT_STATUSES,
            selected_status=status,
        )

    @app.route("/reports/<int:report_id>")
    @role_required("житель")
    def report_detail(report_id: int):
        row = get_db().execute(
            "SELECT id, category, summary, status, created_at FROM reports WHERE id = ? AND owner_sub = ?",
            (report_id, current_user()["sub"]),
        ).fetchone()
        if row is None:
            log("WARN", "access.denied", "failure", "чужое или отсутствующее сообщение", details={"report_id": report_id})
            abort(404)
        log("INFO", "soc.report.viewed", "success", "житель открыл своё сообщение", details={"report_id": report_id})
        return render_template("report_detail.html", row=row, categories=REPORT_CATEGORIES, statuses=REPORT_STATUSES)

    @app.route("/reports/queue")
    @role_required("аналитик_soc")
    def report_queue():
        status = request.args.get("status", "").strip()
        if status and status not in REPORT_STATUSES:
            abort(400, "Недопустимый статус.")
        where = " WHERE status = ?" if status else ""
        rows = get_db().execute(
            "SELECT id, category, summary, status, created_at FROM reports" + where + " ORDER BY id DESC LIMIT 100",
            (status,) if status else (),
        ).fetchall()
        return render_template("report_queue.html", rows=rows, categories=REPORT_CATEGORIES, statuses=REPORT_STATUSES, selected_status=status)

    @app.route("/reports/<int:report_id>/review", methods=("POST",))
    @role_required("аналитик_soc")
    def review_report(report_id: int):
        # Статус берём только из фиксированного списка; владелец и другие поля формы игнорируются.
        decision = request.form.get("decision", "")
        if decision not in ("reviewed", "dismissed"):
            abort(400, "Недопустимое решение.")
        db = get_db()
        cur = db.execute(
            "UPDATE reports SET status = ?, reviewer_sub = ?, reviewed_at = strftime('%Y-%m-%d %H:%M:%f', 'now') "
            "WHERE id = ? AND status = 'new'",
            (decision, current_user()["sub"], report_id),
        )
        if cur.rowcount != 1:
            abort(404)
        db.commit()
        log("INFO", "soc.report.reviewed", "success", "сообщение разобрано", details={"report_id": report_id, "decision": decision})
        return redirect(url_for("report_queue"))

    return app
