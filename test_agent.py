"""
Script descartable para probar el agente end-to-end con una alerta de prueba.
Correr: python test_agent.py
Requiere GEMINI_API_KEY en el .env. Usa el mismo user/IP de prueba del
Sprint 2 (jperez / 203.0.113.10) para que get_related_alerts_tool tenga
alertas reales para encontrar.
"""

import uuid
from datetime import datetime, timezone

from agent import triage_alert
from db import init_db

init_db()

alert = {
    "id": str(uuid.uuid4()),
    "wazuh_rule_id": "5712",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "agent_name": "vm-kali",
    "rule_level": 10,
    "rule_description": "sshd: multiples intentos fallidos (posible fuerza bruta)",
    "source_ip": "203.0.113.10",
    "user": "jperez",
}

result = triage_alert(alert)
print(result)
