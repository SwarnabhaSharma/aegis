# Aegis — Autonomous Security Incident Operations Platform

SOC analysts are overwhelmed: thousands of alerts per day, most false positives,
and the real threats hide in noise. AI can help — but uncontrolled LLM autonomy
in security operations is dangerous. A hallucinated response could isolate a
production server or disable a CEO's account.

Aegis solves this with a simple principle: **AI proposes, deterministic controls
dispose**. Five LLM reasoning agents investigate alerts over real Sysmon telemetry;
a policy engine, executor, and verifier — all deterministic — decide, act,
and confirm. The LLM can never mutate incident state or execute actions.

Local-first, no cloud dependencies. Runs on a single laptop with a 9B model.

Measured on the bundled eval corpus with a 9B local model:
precision 1.0, recall 1.0, 0 unsafe actions ([report](evals/report-real-20260823-060037.md)).
Remeasure before quoting: those runs predate prompt v2 and the sampling-temperature
knob below — live runs on Ornith-1.0 turboquant need `LLM_TEMPERATURE=0.6`.
Live-verified 2026-09-06: real model + real winlogbeat telemetry + ES store →
`RESOLVED`, A1–A5 ok, 200 evidence items ([demo](docs/demo-scenario.md)).

## Architecture

```
                        ┌─────────────────────────────┐
                        │  Autonomous Operations Loop  │
                        │  (poll ES → prioritize →     │
                        │   feed alerts into pipeline) │
                        └─────────────┬───────────────┘
                                      │
alert ──► ingest ──► [privacy filter] ──► A1..A5 agentic pipeline ──► policy engine
                                                                              │
                                                        ALLOW │ APPROVE │ DENY
                                                              ▼         ▼
                                                    D1 executor   AWAITING_APPROVAL
                                                              ▼         (operator)
                                                    D2 verifier ──► RESOLVED / REOPENED / ESCALATED

Console UI: http://localhost:8099/dashboard
API docs:   http://localhost:8099/docs
```

Full diagrams: [docs/diagrams.md](docs/diagrams.md) · Design decisions: [docs/adr.md](docs/adr.md)
· Requirement tracker: [docs/gap-audit.md](docs/gap-audit.md)
· Domain vocabulary: [CONTEXT.md](CONTEXT.md)

```
src/aegis/        pipeline: agents/ (A1–A5) · incidents/ (store, schema) · policies/ (engine)
                  privacy/ (gateway) · tools/ (registry, telemetry) · integrations/ (TI, LLM)
                  operations/ (autonomous loop) · api.py (routes + console aggregation)
templates/        12 Jinja pages (dashboard, queue, incident, agents, response, privacy, audit…)
scripts/          run_slice.py (single alert) · run_eval.py (corpus eval)
evals/            corpus.json + per-scenario reports + metrics
tests/            offline unit suite · integration/ (live-ES, needs AEGIS_INTEGRATION=1)
```

## Quickstart

Prereqs: Python ≥3.12; Elasticsearch 8.x reachable (VM or local); llama.cpp
server (`llama-server -m <model.gguf> --port 8080`) for real LLM mode.

```powershell
pip install -r requirements.txt
pip install -e .               # makes `aegis` importable for uvicorn (src layout)
copy .env.example .env        # then set ES_PASSWORD etc. (see table below)

# offline demo — no VM, no LLM needed (in-memory store; nothing persists)
python scripts\run_slice.py --llm fake --telemetry synthetic

# full live: real model + real telemetry from your host
python scripts\run_slice.py --llm real --telemetry real --host <your-hostname>

# durable mode: incidents persisted to Elasticsearch instead of memory
# (default AEGIS_STORE=memory keeps everything in-process; visible in Kibana with es)
$env:AEGIS_STORE="es"; python scripts\run_slice.py --llm fake

# real host telemetry (winlogbeat index) instead of canned data
$env:ES_TELEMETRY_INDEX="winlogbeat-*"; python scripts\run_slice.py --llm real --telemetry real --host <your-hostname>

# API
uvicorn aegis.api:app --port 8099     # console at /dashboard, Swagger at /docs

# evaluation
python scripts\run_eval.py --llm real
```

Tests:

```powershell
python -m pytest --ignore=tests\integration -q      # offline unit suite
$env:AEGIS_INTEGRATION="1"; python -m pytest tests\integration -v   # live-ES
```

## Configuration (.env)

| Var | Default | Purpose |
|---|---|---|
| `ES_HOST` | `http://192.168.56.105:9200` | Elasticsearch endpoint |
| `ES_USER` / `ES_PASSWORD` | elastic / — | ES credentials (gitignored `.env` only) |
| `LLM_BASE_URL` | `http://localhost:8080/v1` | OpenAI-compatible LLM server |
| `LLM_TEMPERATURE` | `0.0` | Sampling temp; `0.5`–`0.6` on Ornith-1.0 turboquant (temp-0 greedy emits bad JSON) |
| `LLM_MODEL` | — | Model id/path (recorded in per-incident manifest) |
| `TI_PROVIDERS` | `local` | TI fan-out, e.g. `local,abuseipdb,virustotal,otx` (+ `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `NVD_API_KEY`) |
| `ES_TELEMETRY_INDEX` | canned synthetic index | telemetry source (`winlogbeat-*` for a real host) |
| `ES_ALERT_INDEX` | `aegis-dev-alerts` | index polled for new alerts |
| `AEGIS_API_KEY` | empty (= open in dev) | gates API (401) and console (403 page) when set |
| `AEGIS_STORE` | memory | `es` = persist incidents/steps/audit to ES |
| `AEGIS_SAFE_MODE` | off | pause autonomy + force approvals |
| `AEGIS_REQUIRE_APPROVAL` | off | human gate on every action |
| `AEGIS_DISABLE_AGENTS` | — | comma list, e.g. `A3,A4` |
| `AEGIS_REVOKED_TOOLS` | — | comma list of revoked tool names |
| `AEGIS_LOG_LEVEL` | `INFO` | `DEBUG` for first-run troubleshooting (noisy: per-tool calls) |

## API surface

| Endpoint | Purpose |
|---|---|
| `POST /incidents` | ingest alert |
| `GET /incidents/{id}` · `/timeline` · `/evidence` | inspect |
| `POST /incidents/{id}/investigate` | run agent pipeline + policy |
| `GET /incidents?q=&sort=&page=` | queue search/sort/pagination |
| `GET /incidents/{id}/replay` | merged chronology (timeline + policy + execution + verification) |
| `GET /api/overview` · `/api/agents/activity` | dashboard stats · global agent feed |
| `POST /incidents/{id}/approve` | operator authorization gate |
| `GET /controls` · `POST /controls/{action}` | emergency controls (pause/safe-mode/disable/revoke) |
| `POST /operations/start` · `/stop` · `/status` | autonomous operations loop |
| `GET /operations/approvals` · `POST .../approve` · `.../deny` | approval queue |
| `GET /dashboard` · `/` · `/console/agents` | overview · queue · agent activity |
| `GET /incidents/{id}/console` · `/privacy` · `/response` | detail + phase stepper · data-access log · response chain |
| `GET /console/operations` · `/console/controls` · `/console/audit` | loop + approvals · emergency switches · filterable audit |

Console tour and screen-by-screen demo: [docs/demo-scenario.md](docs/demo-scenario.md)
· UI design record: [docs/ui-plan.md](docs/ui-plan.md).

## Safety model

- **Authority**: agents propose via JSON; only the orchestrator/operator mutate
  state; response tools are D1-gated in the registry; execution is verified by
  the independent D2 verifier (never trusted from action results).
- **Fail-safe**: LLM down/malformed → retry once → corrective re-prompt →
  deterministic degrade → incident ESCALATED. Budgets cap steps/tool-calls/time.
- **Untrusted telemetry**: evidence is wrapped as data blocks; injection
  patterns are flagged to audit; fabricated evidence_ids are stripped.
- **Privacy**: secrets/PII detected and redacted before AI views; decisions
  audited. Emergency controls operate without the LLM.
- **Console/API auth**: when `AEGIS_API_KEY` is set, every route requires it —
  browsers get a 403 page, API clients get JSON 401. Open only in dev (unset).
- **Output encoding**: console renders API/telemetry strings via `textContent`
  only — no `innerHTML` sinks; a regression test scans all templates.

Threat analysis: [docs/threat-model.md](docs/threat-model.md).

## Evaluation

Strongest proof artifact: the per-scenario report
([report-real-20260823-060037.md](evals/report-real-20260823-060037.md)) —
metrics plus what happened in every scenario, including where the model
fabricated evidence references and the validator stripped them.

`evals/corpus.json` holds the labeled scenarios (malicious/benign/ambiguous,
incl. prompt-injection-in-telemetry). `scripts/run_eval.py` runs them through
the real pipeline and writes fresh metrics + reports into `evals/`.
Rerun before quoting numbers: the checked-in report predates prompt v2 and
the `LLM_TEMPERATURE` knob.

## Limitations

- Simulated executor/verifier backends (ADR-013): isolation state is
  in-memory; contract matches a real EDR backend swap.
- Console UI: Jinja2 server-rendered, no build step (ADR-008). No threat map,
  no global search, no ad-hoc query console — deferred, see [ui-plan](docs/ui-plan.md).
- Detection quality depends on the local model — measure with your own
  model via `run_eval.py`, do not assume these numbers transfer.
