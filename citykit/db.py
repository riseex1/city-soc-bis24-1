"""База района: SQLite в папке DATA_DIR (в Docker — том). Запросы — только с параметрами."""

import sqlite3

from flask import current_app, g


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_schema(app, schema_sql: str) -> None:
    """Таблицы создаются при запуске (CREATE TABLE IF NOT EXISTS) — отдельная команда не нужна."""
    con = sqlite3.connect(app.config["DATABASE"])
    try:
        con.executescript(schema_sql)
        con.commit()
    finally:
        con.close()
