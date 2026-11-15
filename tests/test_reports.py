"""Пара 5: роль, владелец, белый список и журнал для функций SOC."""

import re

from conftest import csrf, login_as
from citykit import get_db


def submit(client, *, category="fraud", summary="Подозрительная попытка обмана", **extra):
    token = csrf(client, "/reports")
    return client.post(
        "/reports",
        data={"csrf_token": token, "category": category, "summary": summary, **extra},
        follow_redirects=True,
    )


def test_resident_creates_own_report_and_whitelist(client, app, bus):
    login_as(client, "ivanov", "житель")
    response = submit(client, owner_sub="sub-petrova", status="reviewed", reviewer_sub="sub-admin")
    assert response.status_code == 200
    assert "Моё сообщение № 1" in response.get_data(as_text=True)
    with app.app_context():
        row = get_db().execute("SELECT owner_sub, status, reviewer_sub FROM reports WHERE id = 1").fetchone()
        assert tuple(row) == ("sub-ivanov", "new", None)
    assert any(p.get("event") == "soc.report.created" for _, p in bus.published if isinstance(p, dict))
    assert "Подозрительная попытка обмана" not in str(bus.published)


def test_create_report_rejects_wrong_role_and_bad_fields(client, app):
    login_as(client, "ivanov", "житель")
    assert submit(client).status_code == 200
    login_as(client, "analyst", "аналитик_soc")
    token = csrf(client, "/reports/queue")
    assert client.post("/reports", data={"csrf_token": token, "category": "fraud", "summary": "Достаточно длинное описание"}).status_code == 403
    login_as(client, "ivanov", "житель")
    assert submit(client, category="forged").status_code == 400
    assert submit(client, summary="коротко").status_code == 400
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 1


def test_resident_sees_only_own_report(client):
    login_as(client, "petrova", "житель")
    assert submit(client).status_code == 200
    login_as(client, "ivanov", "житель")
    assert client.get("/reports/1").status_code == 404
    assert "Подозрительная попытка обмана" not in client.get("/reports").get_data(as_text=True)


def test_report_detail_allowed_for_owner(client):
    login_as(client, "ivanov", "житель")
    assert submit(client).status_code == 200
    assert client.get("/reports/1").status_code == 200


def test_report_detail_denies_foreign_and_wrong_role(client):
    login_as(client, "petrova", "житель")
    submit(client)
    login_as(client, "ivanov", "житель")
    assert client.get("/reports/1").status_code == 404
    login_as(client, "analyst", "аналитик_soc")
    assert client.get("/reports/1").status_code == 403


def test_analyst_reviews_report_and_audit_has_no_body(client, app, bus):
    login_as(client, "ivanov", "житель")
    submit(client)
    login_as(client, "analyst", "аналитик_soc")
    token = csrf(client, "/reports/queue")
    response = client.post("/reports/1/review", data={"csrf_token": token, "decision": "reviewed", "owner_sub": "forged"}, follow_redirects=True)
    assert response.status_code == 200
    assert "проверено" in response.get_data(as_text=True)
    with app.app_context():
        row = get_db().execute("SELECT owner_sub, status, reviewer_sub FROM reports WHERE id = 1").fetchone()
        assert tuple(row) == ("sub-ivanov", "reviewed", "sub-analyst")
    assert any(p.get("event") == "soc.report.reviewed" for _, p in bus.published if isinstance(p, dict))
    assert "Подозрительная попытка обмана" not in str(bus.published)


def test_review_report_missing_object_is_404(client):
    login_as(client, "analyst", "аналитик_soc")
    token = csrf(client, "/reports/queue")
    assert client.post("/reports/999/review", data={"csrf_token": token, "decision": "reviewed"}).status_code == 404


def test_review_report_denies_resident_before_object_lookup(client):
    login_as(client, "ivanov", "житель")
    token = csrf(client, "/reports")
    assert client.post("/reports/999/review", data={"csrf_token": token, "decision": "reviewed"}).status_code == 403


def test_analyst_queue_role_and_decision_whitelist(client, app):
    login_as(client, "ivanov", "житель")
    assert client.get("/reports/queue").status_code == 403
    submit(client)
    login_as(client, "analyst", "аналитик_soc")
    assert client.get("/reports/queue").status_code == 200
    token = csrf(client, "/reports/queue")
    assert client.post("/reports/1/review", data={"csrf_token": token, "decision": "superadmin"}).status_code == 400
    with app.app_context():
        assert get_db().execute("SELECT status FROM reports WHERE id = 1").fetchone()[0] == "new"


def test_analyst_filters_queue_by_status(client):
    login_as(client, "ivanov", "житель")
    submit(client, summary="Первое сообщение для проверки")
    submit(client, summary="Второе сообщение для проверки")
    login_as(client, "analyst", "аналитик_soc")
    token = csrf(client, "/reports/queue")
    assert client.post("/reports/1/review", data={"csrf_token": token, "decision": "reviewed"}).status_code == 302

    new_queue = client.get("/reports/queue?status=new").get_data(as_text=True)
    assert "Второе сообщение для проверки" in new_queue
    assert "Первое сообщение для проверки" not in new_queue

    reviewed_queue = client.get("/reports/queue?status=reviewed").get_data(as_text=True)
    assert "Первое сообщение для проверки" in reviewed_queue
    assert "Второе сообщение для проверки" not in reviewed_queue
    assert client.get("/reports/queue?status=invalid").status_code == 400


def report_ids(client, url):
    """Номера сообщений, которые видны в таблице «Мои сообщения» (по ссылкам на карточки)."""
    html = client.get(url).get_data(as_text=True)
    return set(re.findall(r'href="/reports/(\d+)"', html))


def test_resident_filters_own_reports_by_status(client):
    login_as(client, "petrova", "житель")
    submit(client, summary="Сообщение Петровой, чужое")  # № 1
    login_as(client, "ivanov", "житель")
    submit(client, summary="Первое сообщение Иванова")  # № 2
    submit(client, summary="Второе сообщение Иванова")  # № 3
    submit(client, summary="Третье сообщение Иванова")  # № 4

    login_as(client, "analyst", "аналитик_soc")
    token = csrf(client, "/reports/queue")
    assert client.post("/reports/2/review", data={"csrf_token": token, "decision": "reviewed"}).status_code == 302
    assert client.post("/reports/3/review", data={"csrf_token": token, "decision": "dismissed"}).status_code == 302

    login_as(client, "ivanov", "житель")
    # Без фильтра и при любом статусе житель видит только свои сообщения (№ 1 — чужое).
    assert report_ids(client, "/reports") == {"2", "3", "4"}
    assert report_ids(client, "/reports?status=") == {"2", "3", "4"}
    assert report_ids(client, "/reports?status=new") == {"4"}
    assert report_ids(client, "/reports?status=reviewed") == {"2"}
    assert report_ids(client, "/reports?status=dismissed") == {"3"}

    # Недопустимый статус отклоняется, а у другого жителя фильтр не показывает чужое.
    assert client.get("/reports?status=invalid").status_code == 400
    login_as(client, "petrova", "житель")
    assert report_ids(client, "/reports?status=new") == {"1"}
    assert report_ids(client, "/reports?status=reviewed") == set()
