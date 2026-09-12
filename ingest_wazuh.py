"""
SOC Copilot - ingesta de alertas desde Wazuh
Sprint 1: en vez de configurar un webhook dentro de Wazuh (mas complejo
de armar y de explicar), este script le pregunta activamente al indexer
(OpenSearch) por alertas nuevas cada X segundos, las normaliza a nuestro
formato, y se las manda a nuestra propia API (POST /alerts).

Correr en una terminal aparte, con la API ya corriendo:
    python ingest_wazuh.py
"""

import time
from pathlib import Path

import requests
import urllib3

# El indexer usa un certificado self-signed, igual que el dashboard.
# Desactivamos el warning de verificacion SSL solo para este entorno local.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER_URL = "https://localhost:9200/wazuh-alerts-*/_search"
INDEXER_USER = "admin"
INDEXER_PASSWORD = "SecretPassword"  # la misma que usaste para entrar al dashboard

API_URL = "http://localhost:8000/alerts"

STATE_FILE = Path(__file__).parent / "last_timestamp.txt"
POLL_INTERVAL_SECONDS = 20


def get_last_timestamp() -> str:
    if STATE_FILE.exists():
        return STATE_FILE.read_text().strip()
    return "now-10m"  # la primera vez, traemos solo los ultimos 10 minutos


def save_last_timestamp(ts: str) -> None:
    STATE_FILE.write_text(ts)


def fetch_new_alerts(since: str) -> list[dict]:
    query = {
        "size": 100,
        "sort": [{"timestamp": "asc"}],
        "query": {"range": {"timestamp": {"gt": since}}},
    }
    resp = requests.post(
        INDEXER_URL,
        auth=(INDEXER_USER, INDEXER_PASSWORD),
        json=query,
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json().get("hits", {}).get("hits", [])


def normalize(hit: dict) -> dict:
    source = hit.get("_source", {})
    rule = source.get("rule", {})
    agent = source.get("agent", {})
    data = source.get("data", {})
    return {
        "wazuh_rule_id": str(rule.get("id")),
        "timestamp": source.get("timestamp"),
        "agent_name": agent.get("name"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "source_ip": data.get("srcip"),
        "user": data.get("srcuser") or data.get("dstuser"),
        "raw_json": source,
    }


def main() -> None:
    since = get_last_timestamp()
    print(f"Iniciando polling de Wazuh cada {POLL_INTERVAL_SECONDS}s (desde {since})")
    while True:
        try:
            hits = fetch_new_alerts(since)
            for hit in hits:
                alert = normalize(hit)
                requests.post(API_URL, json=alert, timeout=5)
                since = alert["timestamp"]
            if hits:
                save_last_timestamp(since)
                print(f"Procesadas {len(hits)} alertas nuevas.")
        except Exception as exc:
            print("Error en el ciclo de polling:", exc)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
