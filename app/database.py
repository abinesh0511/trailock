"""SQLite storage for Trailock. The database file is created automatically."""
import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.getenv("TRAILOCK_DB", Path(__file__).resolve().parent.parent / "trailock.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    pw_hash     TEXT NOT NULL,
    salt        TEXT NOT NULL,
    is_admin    INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    ip          TEXT,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS login_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    email         TEXT,
    user_id       INTEGER,
    ip            TEXT NOT NULL,
    country       TEXT,
    country_code  TEXT,
    city          TEXT,
    lat           REAL,
    lon           REAL,
    isp           TEXT,
    risky_network INTEGER DEFAULT 0,
    user_agent    TEXT,
    device_id     TEXT,
    success       INTEGER NOT NULL,
    score         INTEGER NOT NULL,
    action        TEXT NOT NULL,
    reasons       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ip   ON login_events(ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_user ON login_events(user_id, ts);
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip          TEXT PRIMARY KEY,
    reason      TEXT,
    created_at  REAL NOT NULL,
    until       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS otp_challenges (
    id          TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    event_id    INTEGER NOT NULL,
    code        TEXT NOT NULL,
    ip          TEXT,
    attempts    INTEGER NOT NULL DEFAULT 0,
    used        INTEGER NOT NULL DEFAULT 0,
    expires_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS geo_cache (
    ip    TEXT PRIMARY KEY,
    data  TEXT NOT NULL,
    ts    REAL NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
