"""
SOC Copilot - capa de base de datos
Sprint 1: SQLite simple para guardar las alertas crudas que llegan de Wazuh.
Mas adelante (Sprint 3) vamos a sumar la tabla `cases` para lo que produce
el agente LLM.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent / "soc_copilot.db"


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS raw_alerts (
                id TEXT PRIMARY KEY,
                wazuh_rule_id TEXT,
                timestamp TEXT,
                agent_name TEXT,
                rule_level INTEGER,
                rule_description TEXT,
                source_ip TEXT,
                user TEXT,
                raw_json TEXT
            )
            """
        )


def insert_alert(alert: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO raw_alerts
                (id, wazuh_rule_id, timestamp, agent_name, rule_level,
                 rule_description, source_ip, user, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert["id"],
                alert.get("wazuh_rule_id"),
                alert.get("timestamp"),
                alert.get("agent_name"),
                alert.get("rule_level"),
                alert.get("rule_description"),
                alert.get("source_ip"),
                alert.get("user"),
                alert.get("raw_json"),
            ),
        )


def list_alerts(limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM raw_alerts ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
