"""
SOC Copilot - enriquecimiento con threat intelligence
Sprint 2: consulta la reputacion de una IP en AbuseIPDB, con cache local
de 24hs para no gastar cuota de la API de forma innecesaria si la misma
IP aparece varias veces.
"""

import os
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

from db import get_cached_enrichment, save_enrichment

load_dotenv()

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_TTL_HOURS = 24


def check_ip_reputation(ip: str) -> dict:
    """Devuelve {ip, abuse_score, country, from_cache}.
    abuse_score va de 0 (limpia) a 100 (reportada como maliciosa)."""

    cached = get_cached_enrichment(ip)
    if cached:
        checked_at = datetime.fromisoformat(cached["checked_at"])
        if datetime.now(timezone.utc) - checked_at < timedelta(hours=CACHE_TTL_HOURS):
            return {
                "ip": ip,
                "abuse_score": cached["abuse_score"],
                "country": cached["country"],
                "from_cache": True,
            }

    if not ABUSEIPDB_API_KEY:
        raise RuntimeError(
            "Falta la variable de entorno ABUSEIPDB_API_KEY. "
            "Corre: export ABUSEIPDB_API_KEY='tu_key_aca' antes de levantar la API."
        )

    resp = requests.get(
        ABUSEIPDB_URL,
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})

    abuse_score = data.get("abuseConfidenceScore", 0)
    country = data.get("countryCode") or "unknown"

    save_enrichment(ip, abuse_score, country)

    return {"ip": ip, "abuse_score": abuse_score, "country": country, "from_cache": False}