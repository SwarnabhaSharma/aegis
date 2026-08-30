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

## Architecture

```
alert ──► ingest ──► [privacy filter] ──► A1..A5 agentic pipeline ──► policy engine
                                                                              │
                                                        ALLOW │ APPROVE │ DENY
                                                              ▼         ▼
                                                    D1 executor   AWAITING_APPROVAL
                                                              ▼         (operator)
                                                    D2 verifier ──► RESOLVED / REOPENED / ESCALATED
```

Full diagrams: [docs/diagrams.md](docs/diagrams.md) · Design decisions: [docs/adr.md](docs/adr.md)
· Requirement tracker: [docs/gap-audit.md](docs/gap-audit.md)

## Quickstart

Prereqs: Python ≥3.12; Elasticsearch 8.x reachable (VM or local); llama.cpp
server (`llama-server -m <model.gguf> --port 8080`) for real LLM mode.

```powershell
pip install -r requirements.txt
copy .env.example .env        # then set ES_PASSWORD etc. (see table below)

# offline demo — no VM, no LLM needed
python scripts\run_slice.py --llm fake --telemetry synthetic

# full live: real model + real telemetry from your host
python scripts\run_slice.py --llm real --telemetry real --host <your-hostname>

# durable mode: incidents persisted to Elasticsearch (visible in Kibana)
$env:AEGIS_STORE="es"; python scripts\run_slice.py --llm fake

# API
uvicorn aegis.api:app --port 8099     # Swagger at /docs

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
| `LLM_MODEL` | — | Model id/path (recorded in per-incident manifest) |
| `AEGIS_STORE` | memory | `es` = persist incidents/steps/audit to ES |
| `AEGIS_SAFE_MODE` | off | pause autonomy + force approvals |
| `AEGIS_REQUIRE_APPROVAL` | off | human gate on every action |
| `AEGIS_DISABLE_AGENTS` | — | comma list, e.g. `A3,A4` |
| `AEGIS_REVOKED_TOOLS` | — | comma list of revoked tool names |

## API surface

| Endpoint | Purpose |
|---|---|
| `POST /incidents` | ingest alert |
| `GET /incidents/{id}` · `/timeline` · `/evidence` | inspect |
| `POST /incidents/{id}/investigate` | run agent pipeline + policy |
| `POST /incidents/{id}/approve` | operator authorization gate |
| `GET /controls` · `POST /controls/{action}` | emergency controls (pause/safe-mode/disable/revoke) |

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

Threat analysis: [docs/threat-model.md](docs/threat-model.md).

## Evaluation

`evals/corpus.json` holds labeled scenarios (malicious/benign/ambiguous,
incl. prompt-injection-in-telemetry). `scripts/run_eval.py` runs them through
the real pipeline and writes metrics + per-scenario reports into `evals/`.
Current measured limitations are listed in the report — e.g. the local 9B
model fabricates evidence references routinely; the validator strips them.

## Limitations

- Simulated executor/verifier backends (ADR-013): isolation state is
  in-memory; contract matches a real EDR backend swap.
- Local single-node ES; audit hash-chaining not yet implemented.
- Console UI not built; API is the interface (see gap-audit §28).
- Detection quality depends on the local model — measure with your own
  model via `run_eval.py`, do not assume these numbers transfer.
