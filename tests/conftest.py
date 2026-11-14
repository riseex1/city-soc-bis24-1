import re
import sys
from pathlib import Path

import pytest

try:
    import citykit  # noqa: F401 — в архиве района citykit лежит рядом
except ImportError:  # в репозитории курса — общая копия в g2/city/citykit
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from citykit.bus import MemoryBus


@pytest.fixture
def bus():
    return MemoryBus()


@pytest.fixture
def app(tmp_path, bus):
    from app import create_app

    return create_app({"TESTING": True, "SECRET_KEY": "test", "DATABASE": str(tmp_path / "t.sqlite"), "BUS": bus})


@pytest.fixture
def client(app):
    return app.test_client()


def login_as(client, username, *roles, sub=None):
    """Вместо настоящего входа через Keycloak кладём пользователя в сессию."""
    with client.session_transaction() as s:
        s.clear()
        s["user"] = {
            "sub": sub or f"sub-{username}",
            "username": username,
            "name": username.title(),
            "roles": list(roles),
        }


def csrf(client, url="/"):
    html = client.get(url).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, f"нет CSRF-токена на {url}"
    return m.group(1)
