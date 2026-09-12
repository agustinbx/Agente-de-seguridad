"""
SOC Copilot - agente LLM de triage
Sprint 3: usa Gemini con function calling para decidir la severidad de una
alerta. El modelo llama a las tools de enriquecimiento/correlacion antes de
opinar (no adivina), y persiste su veredicto final llamando a save_case.
"""

import os

from dotenv import load_dotenv
from google import genai
from google.genai import types

from db import get_related_alerts, get_user_history, save_case
from enrichment import check_ip_reputation

load_dotenv()

MODEL_NAME = "gemini-3.5-flash"

_client: genai.Client | None = None


def _get_client() -> genai.Client:
    global _client
    if _client is None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "Falta la variable de entorno GEMINI_API_KEY. Agregala al "
                "archivo .env antes de correr el agente."
            )
        _client = genai.Client(api_key=api_key)
    return _client

SYSTEM_PROMPT = """
Sos un analista de seguridad SOC nivel 1 con experiencia, encargado de hacer
triage de alertas generadas por Wazuh.

Reglas:
1. Nunca decidas la severidad a ojo. Antes de opinar, usa las herramientas
   disponibles para juntar contexto: reputacion de la IP involucrada,
   alertas relacionadas del mismo usuario/IP en las ultimas horas, e
   historial del usuario.
2. Si la alerta no tiene IP o usuario, no llames a las tools que los
   necesitan para ese dato.
3. Mapea la alerta a una tecnica de MITRE ATT&CK (formato "T1110 - Brute
   Force") solo si estas realmente seguro; si no, dejalo vacio en vez de
   inventar una.
4. La severidad final debe ser una de: critical, high, medium, low, info.
5. Una vez que reuniste el contexto que necesitas, llama SIEMPRE a la tool
   save_case_tool con tu veredicto. Es la unica forma de que el caso quede
   guardado - si no la llamas, tu analisis se pierde.
6. Se conciso: el resumen y la recomendacion son para un analista humano que
   va a leer decenas de casos por dia.
7. Todos los parametros de las tools son obligatorios. Si alguno no aplica,
   mandalo igual como "" (string vacio) o [] (lista vacia) segun el tipo -
   nunca lo omitas. Para get_related_alerts_tool, si no tenes una ventana de
   tiempo especifica en mente, usa 60 minutos.
""".strip()


def check_ip_reputation_tool(ip: str) -> dict:
    """Consulta la reputacion de una IP en AbuseIPDB (score de 0 a 100 y
    pais), usando cache local de 24hs.

    Args:
        ip: La direccion IP a consultar, ej. "203.0.113.10".
    """
    return check_ip_reputation(ip)


def get_user_history_tool(username: str) -> dict:
    """Busca el historial de un usuario: cuantas alertas tuvo antes, que IPs
    usa habitualmente, y cuantos casos previos se generaron sobre el.

    Args:
        username: El nombre de usuario a buscar.
    """
    return get_user_history(username)


def _build_alert_prompt(alert: dict) -> str:
    return (
        "Nueva alerta de Wazuh para triagear:\n"
        f"- id: {alert['id']}\n"
        f"- regla Wazuh: {alert.get('wazuh_rule_id')}\n"
        f"- descripcion: {alert.get('rule_description')}\n"
        f"- nivel Wazuh (0-15): {alert.get('rule_level')}\n"
        f"- timestamp: {alert.get('timestamp')}\n"
        f"- agente/host: {alert.get('agent_name')}\n"
        f"- usuario: {alert.get('user') or '(no aplica)'}\n"
        f"- IP origen: {alert.get('source_ip') or '(no aplica)'}\n"
    )


def triage_alert(alert: dict) -> dict:
    """Corre el agente sobre una alerta ya guardada y devuelve el caso
    creado. `alert` es un dict como los que devuelve db.list_alerts()."""
    alert_id = alert["id"]
    result: dict = {}

    def get_related_alerts_tool(user: str, ip: str, minutes: int) -> list[dict]:
        """Busca otras alertas del mismo usuario y/o la misma IP origen
        dentro de una ventana de tiempo reciente, para detectar patrones
        (ej. varios intentos de login fallido seguidos).

        Args:
            user: Nombre de usuario a buscar, o "" si no aplica.
            ip: IP origen a buscar, o "" si no aplica.
            minutes: Ventana de tiempo hacia atras, en minutos (ej. 60).
        """
        return get_related_alerts(
            user=user or None, ip=ip or None, minutes=minutes, exclude_id=alert_id
        )

    def save_case_tool(
        severity: str,
        title: str,
        summary: str,
        recommendation: str,
        mitre_technique: str,
        related_alert_ids: list[str],
    ) -> dict:
        """Persiste el veredicto final del triage. Llamala una sola vez, al
        final, cuando ya tengas toda la informacion que necesitas.

        Args:
            severity: Una de "critical", "high", "medium", "low", "info".
            title: Resumen corto, ej. "Posible fuerza bruta contra jperez".
            summary: Explicacion en lenguaje natural de por que se eligio
                esta severidad.
            recommendation: Proximos pasos sugeridos para el analista humano.
            mitre_technique: Ej. "T1110 - Brute Force", o "" si no aplica.
            related_alert_ids: IDs de otras alertas relacionadas que hayas
                encontrado con get_related_alerts_tool, o [] si no hay.
        """
        ids = set(related_alert_ids)
        ids.add(alert_id)
        case_id = save_case(
            related_alert_ids=sorted(ids),
            severity=severity,
            title=title,
            summary=summary,
            recommendation=recommendation,
            mitre_technique=mitre_technique or None,
        )
        result.update(
            case_id=case_id,
            severity=severity,
            title=title,
            summary=summary,
            recommendation=recommendation,
            mitre_technique=mitre_technique or None,
            related_alert_ids=sorted(ids),
        )
        return {"case_id": case_id, "status": "saved"}

    _get_client().models.generate_content(
        model=MODEL_NAME,
        contents=_build_alert_prompt(alert),
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            tools=[
                check_ip_reputation_tool,
                get_related_alerts_tool,
                get_user_history_tool,
                save_case_tool,
            ],
        ),
    )

    if "case_id" not in result:
        raise RuntimeError(
            "El agente no llamo a save_case_tool - no se genero ningun "
            "caso para esta alerta."
        )

    return result
