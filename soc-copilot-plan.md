# SOC Copilot — Plan de proyecto

Agente de triage de alertas de seguridad asistido por IA. Este documento es tu referencia durante todo el desarrollo: arquitectura, diseño, plan de estudio y tareas divididas en sprints.

---

## 1. Resumen del proyecto

**Qué es:** un sistema que recibe alertas de seguridad generadas por Wazuh (SIEM/EDR open source), las enriquece con contexto externo, las correlaciona entre sí, y usa un LLM con function calling para priorizarlas y explicarlas en lenguaje natural. Todo se ve en un dashboard tipo "cola de incidentes ya triageados", no una lista cruda de alertas.

**Qué NO es:** no es un antivirus, no reemplaza a Wazuh, no detecta nada por sí mismo — la detección la hace Wazuh. El valor del proyecto está en la capa de razonamiento e interpretación.

**Por qué importa:** resuelve el problema de "alert fatigue" que sufren los equipos de seguridad reales. Es la misma categoría de producto que startups como Dropzone AI o Prophet Security están vendiendo hoy.

---

## 2. Arquitectura

```
┌─────────┐      ┌───────────────┐      ┌──────────────┐      ┌───────────┐
│  Tu PC  │ ───► │ Wazuh manager │ ───► │  Agente LLM   │ ───► │ Dashboard │
│ (agente │      │ (indexa y     │      │ (FastAPI +    │      │ (casos    │
│ Wazuh)  │      │  genera       │      │  tool use +   │      │  priori-  │
│         │      │  alertas)     │      │  correlación) │      │  zados)   │
└─────────┘      └───────────────┘      └──────┬────────┘      └───────────┘
                                                 │
                                          ┌──────▼────────┐
                                          │ APIs externas │
                                          │ (AbuseIPDB,   │
                                          │  geolocation) │
                                          └───────────────┘
```

**Componentes:**

1. **Wazuh agent** — instalado en tu PC (o VM), genera eventos: FIM (integridad de archivos), logs de autenticación, inventario de procesos.
2. **Wazuh manager** — recibe eventos, aplica reglas, genera alertas en formato JSON. Corre en Docker.
3. **Alert ingestion API** (FastAPI) — se suscribe a las alertas de Wazuh (vía webhook o consultando su API/Elasticsearch backend), las normaliza y las guarda.
4. **Agente LLM** — el corazón del proyecto. Recibe alertas nuevas, decide qué herramientas llamar (reputación de IP, historial de usuario, alertas relacionadas), razona sobre el contexto, y produce un veredicto: severidad + explicación + recomendación + mapeo a MITRE ATT&CK.
5. **Base de datos** — SQLite o PostgreSQL. Guarda alertas crudas, casos ya procesados, y el historial de decisiones del agente.
6. **Dashboard** — Streamlit (para MVP rápido) o Next.js (si querés algo más pulido para portfolio). Muestra la cola de casos, permite hacer preguntas de seguimiento al agente sobre un caso puntual.

---

## 3. Stack tecnológico

| Capa | Tecnología | Alternativa |
|---|---|---|
| SIEM | Wazuh (Docker) | — |
| Backend / API | Python + FastAPI | — |
| Agente / LLM | API de Anthropic o OpenAI, con tool use | Modelo local (Ollama) si querés que sea 100% gratis |
| Base de datos | SQLite (MVP) | PostgreSQL (si querés mostrar algo más "producción") |
| Dashboard | Streamlit (MVP rápido) | Next.js + Tailwind (más pulido visualmente) |
| Threat intel | AbuseIPDB API (gratis, con límite) | VirusTotal API |
| Infraestructura | Docker Compose | — |

---

## 4. Esquema de datos

### Tabla `raw_alerts` (lo que llega de Wazuh, sin procesar)

| Campo | Tipo | Descripción |
|---|---|---|
| id | UUID | identificador único |
| wazuh_rule_id | string | ID de la regla que disparó Wazuh |
| timestamp | datetime | cuándo ocurrió |
| agent_name | string | qué máquina generó el evento |
| rule_level | int | severidad según Wazuh (0-15) |
| rule_description | string | descripción de la regla |
| source_ip | string, nullable | IP origen si aplica |
| user | string, nullable | usuario involucrado si aplica |
| raw_json | JSON | el payload completo de Wazuh |

### Tabla `cases` (lo que produce el agente)

| Campo | Tipo | Descripción |
|---|---|---|
| id | UUID | identificador único |
| related_alert_ids | array de UUID | qué alertas crudas componen este caso |
| severity | enum | critical / high / medium / low / info |
| title | string | resumen corto, ej. "Posible cuenta comprometida (jperez)" |
| summary | text | explicación en lenguaje natural |
| mitre_technique | string, nullable | ej. "T1110 - Brute Force" |
| recommendation | text | próximos pasos sugeridos |
| status | enum | new / reviewing / resolved / false_positive |
| created_at | datetime | — |

### Tabla `enrichment_cache` (para no repetir llamadas a APIs externas)

| Campo | Tipo | Descripción |
|---|---|---|
| ip | string | clave |
| abuse_score | int | resultado de AbuseIPDB |
| country | string | geolocalización |
| checked_at | datetime | para invalidar cache vieja |

---

## 5. Diseño del agente (la parte más importante)

### Herramientas (tools) que el agente puede llamar

1. `check_ip_reputation(ip)` → consulta AbuseIPDB, devuelve score y país
2. `get_related_alerts(user_or_ip, time_window_minutes)` → busca en `raw_alerts` otras alertas del mismo usuario/IP en una ventana de tiempo
3. `get_user_history(username)` → busca si este usuario tuvo casos previos, o si esta IP es habitual para él
4. `save_case(...)` → una vez que el agente decide su veredicto, lo persiste en la tabla `cases`

### Flujo de razonamiento esperado

1. Llega una alerta nueva a la API
2. El agente recibe la alerta como contexto inicial
3. El agente decide, usando tool use, qué información adicional necesita (no todo de una, es iterativo)
4. Con el contexto reunido, arma su veredicto: severidad, resumen, técnica MITRE si aplica, recomendación
5. Llama a `save_case` para persistirlo
6. El dashboard lo muestra

### System prompt — ideas clave a incluir

- Rol: "sos un analista SOC nivel 1 experimentado, tu trabajo es hacer triage de alertas"
- Instrucción explícita de usar las tools antes de decidir severidad (no adivinar)
- Pedir que mapee a MITRE ATT&CK cuando sea posible, pero que no invente técnicas si no está seguro
- Formato de salida estructurado (JSON) para que el dashboard lo pueda renderizar de forma consistente

---

## 6. Plan de estudio

Andá construyendo en paralelo — no esperes a "saber todo" de una sección antes de tocar código.

### Semana 1-2 — Fundamentos de seguridad
- Qué es un SIEM y qué problema resuelve
- Tipos de logs de seguridad (auth, firewall, sistema)
- Introducción a MITRE ATT&CK (tácticas vs técnicas)
- Conceptos de ataques comunes: fuerza bruta, movimiento lateral, exfiltración
- Falso positivo vs falso negativo
- Recurso sugerido: ruta "SOC Level 1" en TryHackMe

### Semana 2-3 (solapada) — Wazuh práctico
- Instalar Wazuh vía Docker Compose
- Entender la arquitectura: agente → manager → indexer
- Cómo se arman las reglas de alerta (XML, niveles de severidad)
- Generar alertas de prueba propias
- Entender el formato JSON de sus alertas

### Semana 3-4 — Python/FastAPI aplicado
- Endpoints y validación con Pydantic
- Consumir APIs externas (`httpx`)
- Manejo de JSON anidado y timestamps
- SQLite básico con SQLAlchemy o el driver directo

### Semana 4-6 — LLM y function calling
- Qué es function calling / tool use en la API de un LLM
- Diferencia entre un prompt simple y un agente que itera en loop
- Prompt engineering: cómo estructurar para razonamiento paso a paso
- Documentación de tool use de Anthropic como referencia práctica

### Semana 6-7 — Integración y threat intel
- API de AbuseIPDB
- Conceptos de geolocalización de IP
- Armar el flujo completo: alerta → enriquecimiento → agente → caso guardado

---

## 7. Task cards por sprint

### Sprint 0 — Setup (objetivo: tener el esqueleto corriendo)
- [ ] Crear repo en GitHub con estructura de carpetas (`/wazuh`, `/api`, `/dashboard`, `/docs`)
- [ ] Levantar Wazuh con Docker Compose siguiendo la doc oficial
- [ ] Confirmar que Wazuh genera al menos una alerta de prueba visible en su dashboard nativo
- [ ] Armar un FastAPI mínimo con un endpoint `/health`

### Sprint 1 — Ingesta de alertas
- [ ] Definir el modelo Pydantic para una alerta de Wazuh
- [ ] Endpoint `POST /alerts` que reciba una alerta y la guarde en `raw_alerts`
- [ ] Conectar Wazuh para que mande sus alertas a este endpoint (webhook o integración)
- [ ] Verificar que una alerta generada en Wazuh termina guardada en tu base

### Sprint 2 — Enriquecimiento
- [ ] Función `check_ip_reputation` contra AbuseIPDB
- [ ] Tabla `enrichment_cache` con expiración simple
- [ ] Función `get_related_alerts` (query por usuario/IP + ventana de tiempo)
- [ ] Tests manuales: verificar que devuelve resultados coherentes con datos de prueba

### Sprint 3 — El agente
- [ ] Definir las tools en el formato que pida la API del LLM elegido
- [ ] Escribir el system prompt del analista SOC
- [ ] Loop de tool use: el agente pide info, vos ejecutás la función real, le devolvés el resultado, repite hasta que decide
- [ ] Función `save_case` que persista el veredicto
- [ ] Probar con 3-5 alertas de prueba distintas y revisar que el razonamiento tenga sentido

### Sprint 4 — Dashboard
- [ ] Vista de lista: casos ordenados por severidad
- [ ] Vista de detalle: click en un caso, ver alertas relacionadas y el razonamiento completo
- [ ] Filtros básicos (por severidad, por estado)
- [ ] Chat de seguimiento: poder preguntarle al agente sobre un caso puntual

### Sprint 5 — Demo y pulido
- [ ] Armar 3-4 escenarios de ataque simulados y reproducibles (para la demo, no depender de que pase algo real)
- [ ] Grabar un video corto (2-3 min) mostrando el flujo completo
- [ ] README con arquitectura, cómo correrlo localmente, y decisiones de diseño explicadas
- [ ] Deploy simple si querés (Docker Compose en un VPS barato) o dejarlo documentado para correr local

---

## 8. Definición de "terminado" (MVP)

El proyecto está en un estado presentable cuando podés:
1. Generar una alerta real o simulada en tu PC (ej. login fallido repetido)
2. Verla aparecer procesada como un caso en el dashboard, con severidad y explicación coherente
3. Explicar en la entrevista/demo por qué el agente decidió esa severidad, mostrando qué tools llamó

## 9. Ideas de extensión (si te sobra tiempo)

- Mapear más técnicas MITRE ATT&CK y mostrar un heatmap de cobertura
- Agregar un modelo de detección de anomalías propio (une esto con tu idea original del EDR) como una fuente de alertas más, además de Wazuh
- Feedback loop: que el analista marque "falso positivo" y eso ajuste futuras decisiones del agente (aunque sea con few-shot examples, no fine-tuning)
- Integrar Slack/Discord para notificaciones de casos críticos
