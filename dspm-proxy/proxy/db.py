"""SQLite storage for intercepted egress events. Shared by the proxy addon
(writer) and the Streamlit dashboard (reader).
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from proxy.config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS egress_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    device_label TEXT,
    device_type TEXT,
    destination_url TEXT NOT NULL,
    method TEXT,
    action TEXT NOT NULL,            -- 'blocked' | 'allowed' | 'error'
    classification TEXT,
    confidence_score REAL,
    entity_type TEXT,
    flagged_content TEXT
);
CREATE INDEX IF NOT EXISTS idx_egress_events_timestamp ON egress_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_egress_events_action ON egress_events (action);
"""


def init_db(db_path: str = DB_PATH) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def get_connection(db_path: str = DB_PATH):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def log_event(
    *,
    timestamp: str,
    source_ip: str,
    device_label: str | None,
    device_type: str | None,
    destination_url: str,
    method: str | None,
    action: str,
    classification: str | None,
    confidence_score: float | None,
    entity_type: str | None,
    flagged_content: str | None,
    db_path: str = DB_PATH,
) -> None:
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO egress_events (
                timestamp, source_ip, device_label, device_type, destination_url,
                method, action, classification, confidence_score, entity_type, flagged_content
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                source_ip,
                device_label,
                device_type,
                destination_url,
                method,
                action,
                classification,
                confidence_score,
                entity_type,
                flagged_content,
            ),
        )
        conn.commit()
