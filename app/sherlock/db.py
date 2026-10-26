import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS apps (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    version     TEXT NOT NULL,
    last_synced TEXT,
    sync_ok     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    app_id           TEXT NOT NULL,
    cve_id           TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
    severity         TEXT,
    score            REAL,
    published        TEXT,
    description      TEXT,
    fixed_in         TEXT,
    patch_available  INTEGER NOT NULL DEFAULT 0,
    patch_url        TEXT,
    kev              INTEGER NOT NULL DEFAULT 0,
    kev_added        TEXT,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    opened_version   TEXT NOT NULL,
    resolved_at      TEXT,
    resolved_version TEXT,
    resolution       TEXT CHECK (resolution IN ('updated', 'not_applicable')),
    PRIMARY KEY (app_id, cve_id)
);

CREATE TABLE IF NOT EXISTS sync_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL,
    message     TEXT
);
"""


def init_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=30) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
    conn.close()


def connect(path: Path, timeout: float = 30) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn
