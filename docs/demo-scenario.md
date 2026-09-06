# AEGIS UI Demo Scenario (MVP close)

## Objective
Show one real incident end-to-end: ingest → investigate → evidence →
assessment → policy → approval → execution → verification → audit.
No fake data. Simulated parts labeled.

## Setup
```powershell
pip install -r requirements.txt
copy .env.example .env   # no keys needed for offline demo
uvicorn aegis.api:app --port 8099
# UI: http://localhost:8099/dashboard | API: /docs
```

Services: none (memory store, FakeLLM). No ES, no llama-server, no API keys.
Live variant needs ES 8.x + `llama-server`; same screens, real telemetry.

## Input
```powershell
python scripts\run_slice.py --llm fake --telemetry synthetic
# or: POST /incidents {"source":"synthetic","fields":{"severity":"high","host":"win-vm"},"incident_type":"powershell"}
# then: POST /incidents/{id}/investigate
```

## Expected workflow (measured 2026-09-06)
```text
TRIAGING → INVESTIGATING → CORRELATING → ASSESSING → RESPONSE_PLANNED
→ AUTHORIZED → EXECUTING → VERIFYING → RESOLVED
evidence persisted: 3 · policy: ALLOW (all conditions met)
verify_host_isolated win-vm: isolated:true passed=True
```

## Screens
1. Overview `/dashboard` — Active 1, trend, type donut, top asset win-vm, recent row, agent feed 5 runs, TI counts, loop status.
2. Queue `/` — search `win-vm` hits 1; severity sort critical-first; pagination.
3. Detail `/incidents/{id}/console` — stepper at Respond/Verify; ATT&CK T1059.001; policy ALLOW; 5 agent runs; evidence 3; replay merged.
4. Agent Activity `/console/agents` — A1-A5 completed + tools used.
5. Response `/incidents/{id}/response` — 6-step chain through PASS verification.
6. Privacy `/incidents/{id}/privacy` — access log 3 rows + classifications.
7. Audit `/console/audit` — filterable event chain + hashes.

## Known limitations (real vs simulated)- REAL: ingest, evidence, graph edges, ATT&CK map, policy gate, approve/deny, audit chain, replay, privacy redaction.
- SIMULATED (ADR-013, labeled in UI): executor isolation state in-memory; verifier reads that state. Swap needs real EDR backend.
- FAKE-FREE: no threat map, no 98% success badge (shows resolved/total), A5 full text noted unpersisted, ES audit index only in durable mode (`AEGIS_STORE=es`).

## Environment matrix (values illustrative — never paste secrets)

| Var | Demo value | Secret | Needed for |
|---|---|---|---|
| `ES_HOST` | `http://192.168.56.105:9200` | no | any ES-backed path |
| `ES_USER` / `ES_PASSWORD` | `elastic` / (from operator) | **yes** | ES store, poll, telemetry reads |
| `ES_TELEMETRY_INDEX` | `winlogbeat-*` (real host) / `telemetry-synthetic-*` (canned) | no | investigation evidence source |
| `ES_ALERT_INDEX` | `aegis-dev-alerts` | no | elastic poll ingestion |
| `AEGIS_STORE` | `es` (durable) / `memory` (offline) | no | persistence backend |
| `LLM_BASE_URL` | `http://localhost:8080/v1` | no | any real-model run |
| `LLM_MODEL` | path to Ornith GGUF | no | model identity (stamped in manifest) |
| `LLM_TEMPERATURE` | `0.6` (Ornith-1.0 turboquant) / `0.0` default | no | sampling; temp-0 greedy degenerates on 1.0 build |
| `TI_PROVIDERS` | `local,abuseipdb,virustotal,otx` | no | live TI fan-out |
| `VT_API_KEY` / `ABUSEIPDB_API_KEY` / `OTX_API_KEY` / `NVD_API_KEY` | (from operator) | **yes** | per-provider live lookups |
| `AEGIS_API_KEY` | (from operator) | **yes** | console + API auth (403/401 when set) |

Paths: offline = none of the above; ES-backed = ES rows; live model = + LLM rows; live TI = + provider rows; real host = winlogbeat index + agent installed on target.

## Regression proof
`pytest --ignore=tests/integration -q` green · 13/13 console+API routes 200 (dashboard, queue, agents, operations, controls, audit, detail, privacy, response, graph, overview, activity, replay).
