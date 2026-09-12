"""
SOC Copilot - API principal
Sprint 1: ademas del /health, ya recibimos y guardamos alertas de Wazuh
a traves de POST /alerts (las manda el script ingest_wazuh.py) y las
podemos consultar con GET /alerts.
"""

import json
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

from db import get_related_alerts, init_db, insert_alert, list_alerts
from enrichment import check_ip_reputation

app = FastAPI(
    title="SOC Copilot API",
    description="Agente de triage de alertas de seguridad asistido por IA",
    version="0.2.0",
)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/health")
def health_check():
    """Endpoint simple para verificar que la API esta corriendo."""
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


class WazuhAlertIn(BaseModel):
    wazuh_rule_id: str | None = None
    timestamp: str | None = None
    agent_name: str | None = None
    rule_level: int | None = None
    rule_description: str | None = None
    source_ip: str | None = None
    user: str | None = None
    raw_json: dict


@app.post("/alerts")
def receive_alert(alert: WazuhAlertIn):
    """Recibe una alerta ya normalizada (la manda ingest_wazuh.py) y la guarda."""
    record = alert.dict()
    record["id"] = str(uuid.uuid4())
    record["raw_json"] = json.dumps(record["raw_json"])
    insert_alert(record)
    return {"status": "stored", "id": record["id"]}


@app.get("/alerts")
def get_alerts(limit: int = 50):
    """Devuelve las ultimas alertas guardadas, para poder verificar que
    el pipeline de ingesta esta funcionando."""
    return list_alerts(limit=limit)


@app.get("/enrich/ip/{ip}")
def enrich_ip(ip: str):
    """Consulta la reputacion de una IP en AbuseIPDB (con cache de 24hs)."""
    return check_ip_reputation(ip)


@app.get("/alerts/related")
def related_alerts(
    user: str | None = None,
    ip: str | None = None,
    minutes: int = 60,
    exclude_id: str | None = None,
):
    """Busca alertas del mismo usuario y/o IP dentro de una ventana de
    tiempo. Es la 'tool' de correlacion que el agente LLM va a usar."""
    return get_related_alerts(user=user, ip=ip, minutes=minutes, exclude_id=exclude_id)


# Para correr localmente:
#   uvicorn main:app --reload --port 8000
# Despues probar en el navegador o con curl:
#   curl http://localhost:8000/health