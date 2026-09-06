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

## Known limitations (real vs simulated)
- REAL: ingest, evidence, graph edges, ATT&CK map, policy gate, approve/deny, audit chain, replay, privacy redaction.
- SIMULATED (ADR-013, labeled in UI): executor isolation state in-memory; verifier reads that state. Swap needs real EDR backend.
- FAKE-FREE: no threat map, no 98% success badge (shows resolved/total), A5 full text noted unpersisted, ES audit index only in durable mode (`AEGIS_STORE=es`).

## Regression proof
`pytest --ignore=tests/integration -q` green · 13/13 console+API routes 200 (dashboard, queue, agents, operations, controls, audit, detail, privacy, response, graph, overview, activity, replay).
