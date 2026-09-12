"""
SOC Copilot - capa de base de datos
Sprint 1: SQLite simple para guardar las alertas crudas que llegan de Wazuh.
Sprint 2: sumamos el cache de enriquecimiento (reputacion de IP) y la
busqueda de alertas relacionadas por usuario/IP.
Mas adelante (Sprint 3) vamos a sumar la tabla `cases` para lo que produce
el agente LLM.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS enrichment_cache (
                ip TEXT PRIMARY KEY,
                abuse_score INTEGER,
                country TEXT,
                checked_at TEXT
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


def get_cached_enrichment(ip: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM enrichment_cache WHERE ip = ?", (ip,)
        ).fetchone()
        return dict(row) if row else None


def save_enrichment(ip: str, abuse_score: int, country: str) -> None:
    checked_at = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO enrichment_cache (ip, abuse_score, country, checked_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                abuse_score = excluded.abuse_score,
                country = excluded.country,
                checked_at = excluded.checked_at
            """,
            (ip, abuse_score, country, checked_at),
        )


def get_related_alerts(
    user: str | None = None,
    ip: str | None = None,
    minutes: int = 60,
    exclude_id: str | None = None,
) -> list[dict]:
    """Busca alertas del mismo usuario y/o IP dentro de una ventana de tiempo.
    Esta es una de las 'tools' que el agente LLM va a poder llamar en el
    Sprint 3 para armar el contexto de un caso."""
    conditions = []
    params: list = []
    if user:
        conditions.append("user = ?")
        params.append(user)
    if ip:
        conditions.append("source_ip = ?")
        params.append(ip)
    if not conditions:
        return []

    where = " OR ".join(conditions)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM raw_alerts WHERE ({where}) ORDER BY timestamp DESC LIMIT 200",
            params,
        ).fetchall()

    now = datetime.now(timezone.utc)
    window = timedelta(minutes=minutes)
    results = []
    for row in rows:
        record = dict(row)
        if exclude_id and record["id"] == exclude_id:
            continue
        try:
            ts = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        if now - ts <= window:
            results.append(record)
    return results