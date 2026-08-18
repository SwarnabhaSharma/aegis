# Aegis — Phase B: Threat Model & Architecture Options

Per doc §31-B. Covers D (threat model), E (architecture options), F (recommendation). **Stops for approval before treating any architecture as selected.**

---

## D. Security Threat Model

Two threat surfaces: (1) the platform as a SOC product, (2) the AI system itself (doc §15). Both apply.

### D.1 Assets

| Asset | Sensitivity | Notes |
|---|---|---|
| Telemetry/evidence store (ES) | HIGH | Full enterprise events, PII, credentials in logs |
| Incident records + AI reasoning | HIGH | Conclusions, hypotheses, planned actions |
| Policy/config | HIGH | Tamper → wrong authorization |
| Audit log | HIGH | Tamper → no accountability |
| Response tool capability | CRITICAL | Misuse = real infra damage |
| LLM runtime + prompts | MEDIUM | Prompt/version drift breaks reproducibility |
| Secrets (ES creds, webhook keys) | CRITICAL | Exposure → full store access |

### D.2 Trust boundaries

```
Telemetry (untrusted) ──► Ingestion ──► Core (trusted) ──► LLM (untrusted reasoning)
TI/lookup APIs (untrusted) ──► Tools ──► Policy (trusted) ──► Executor (trusted, gated)
                                                          ──► Auditor (trusted read)
```

Key rule (doc §15): **all external input is untrusted data, never instructions.**

### D.3 AI-system attack scenarios (doc §15 mapped to defenses)

| # | Attack | Vector | Defense |
|---|---|---|---|
| D-001 | Prompt injection via telemetry | Event fields carry `IGNORE PREVIOUS INSTRUCTIONS...` | Telemetry wrapped as data (delimiters), never concatenated as instructions; injection attempt logged |
| D-002 | Indirect injection via TI | Malicious intel content | TI treated as untrusted data; no TI content in system prompt; source-tagged |
| D-003 | Tool abuse | Agent requests unauthorized action | Tool registry allowlist + typed schemas + policy gate; denied requests audited |
| D-004 | Privilege escalation | Agent asks for higher perms | Immutable agent permission table; authorization layer independent of LLM |
| D-005 | Data exfiltration | Agent requests unrelated sensitive fields | Field-level view control (A-003 stance); per-task data scope; audit data requested vs released |
| D-006 | Agent loops | Agent re-invokes tools/self endlessly | Step budget + time budget per incident phase; hard stop → escalate |
| D-007 | Excessive tool calls | Resource drain | Per-incident tool call quota; rate limits; cost/latency budget |
| D-008 | Hallucinated evidence | Agent claims evidence that doesn't exist | Evidence must reference stored record ID; UI/verifier cross-check exists; unsupported claim flagged |
| D-009 | False remediation | Agent claims success on HTTP 200 | Independent verification required (ADR-009); success = verified state change |
| D-010 | Verification manipulation | Agent influences its own verify result | Verifier separate from executor; verify runs read-only, deterministic, schema-checked |
| D-011 | Malicious TI poisoning | Attacker feeds bad IOCs | TI sources whitelisted; IOC enrichment never drives autonomous action alone; confidence degraded |
| D-012 | Prompt/model version drift | Unreproducible decisions | Version pinning (model/prompt/policy) per incident (ADR logging) |

### D.4 Fail-safe requirements (doc §3.5)

- Missing/contradictory evidence → no autonomous high-risk action
- LLM down → deterministic fallback; no autonomous actions
- Tool/policy/verifier failure → incident goes to human, not silent continue
- Uncertainty ladder: gather evidence → reduce scope → human approval → escalate → stop

---

## E. Architecture Options

Four genuinely different architectures. Each satisfies the lifecycle + authority model from Phase A; they differ in how state, orchestration, and agents are organized.

### E.1 — Modular monolith with central orchestrator (state machine in-process)

- One Python service. Lifecycle = explicit state machine. Orchestrator advances incident through states synchronously. Tools/policy/executor/verifier = internal modules with typed interfaces. Async only where forced (external calls).
- Agents: 1 reasoning component (LLM) invoked at designated states (triage, hypothesis, recommend) — not a multi-agent runtime.

### E.2 — Event-driven workflow engine (async state machine + in-process bus)

- Same monolith, but lifecycle driven by an event bus (in-process queue, e.g. asyncio). State transitions publish events; subscribers (handlers) react. Supports retries, fan-out, eventual consistency. Heavier; more moving parts.

### E.3 — Multi-agent runtime

- Distinct agent objects (triage agent, investigation agent, correlation agent, planner, verifier) with per-agent tool/permission scopes and an orchestrator/router. Closest to doc §7's proposed agent list. LLM invoked per agent step.

### E.4 — Minimal core + scenario plugins (lifecycle core, domain adapters)

- Core = lifecycle, state machine, policy, audit, tool contract. Each incident type (PowerShell exec, password spray, persistence) = plugin: detection query, read tools, policy thresholds, verify checks. Nothing scenario-specific in core.

### E.5 Comparison

Criteria per doc §31-B (1=worst, 5=best).

| Criterion | E.1 monolith | E.2 event-driven | E.3 multi-agent | E.4 core+plugins |
|---|---|---|---|---|
| Security (authority enforcement) | 5 — single choke point | 4 — bus can bypass if sloppy | 3 — many perms to manage | 5 — core owns authority |
| Correctness (state machine) | 5 — synchronous, easy to reason | 3 — async races | 4 | 5 |
| Reliability | 5 — simple failure modes | 3 — queues, retries, ordering | 3 | 5 |
| Complexity | 5 — lowest | 2 — high | 2 — highest | 4 |
| Maintainability | 5 | 3 | 2 | 5 |
| Extensibility | 3 — new scenario = new code | 4 | 4 | 5 — new scenario = plugin |
| Performance | 4 — plenty for local SOC | 3 — bus overhead | 3 | 4 |
| Implementation effort | 5 — least | 2 | 2 | 4 |
| Failure modes | Safe, few | Ordering/duplicate events | Perm sprawl, loops | Safe |
| **Total** | **37** | **24** | **24** | **37** |

### F. Recommendation

**E.4-style core + scenario plugins, organized as E.1 modular monolith.**

- **E.1 chosen for orchestration**: in-process synchronous state machine = simplest correct structure for a lifecycle platform (doc §24, §23 bias). No bus, no microservices, no multi-agent — YAGNI until a concrete requirement forces them.
- **E.4 chosen for domain separation**: incident-type knowledge (queries, policies, verify checks) lives in scenario adapters, not core. This preserves the prior V1 "generic-first, scenarios as plugins" decision and makes Aegis extensible without architectural risk.
- **Agents**: **one** reasoning component (LLM) invoked at triage/hypothesis/recommend states, not a 7-agent runtime (doc §7: fewer agents safer). Deterministic runners (policy, executor, verifier) are not "agents" — they are controlled services.
- **Event-driven / multi-agent rejected**: complexity without a security benefit for a local portfolio platform. Revisit only if: >1 concurrent incident classes need real fan-out, or a concrete async requirement appears.

**What would change the recommendation**:
- Real multi-tenant SOC deployment with thousands of incidents/hour → event-driven (E.2) for backpressure.
- Requirement for independently deployable investigator agents → multi-agent (E.3).
- Demonstration need for "multi-agent" resume narrative → E.3, but security cost is real.

### F.1 Architecture sketch (E.1+E.4)

```
                    ┌─────────────────────────────┐
  Alert source ──►   Ingestion  ──►  Incident store │
                    └──────────────┬──────────────┘
                                   ▼
                    ┌─────────────────────────────┐
                    │  ORCHESTRATOR (state machine) │
                    │  TRIAGE→INVEST→CORRELATE→     │
                    │  ASSESS→PLAN→AUTH→EXECUTE→    │
                    │  VERIFY→RESOLVE/REOPEN        │
                    └───┬─────┬─────┬─────┬─────┬──┘
                        │     │     │     │     │
                   ┌────▼┐ ┌─▼──┐ ┌▼───┐ ┌▼────┐ ┌▼─────┐
                   │Tools │ │LLM │ │Policy│ │Exec │ │Verify │
                   │(read)│ │(reason)│ │engine│ │(sim)│ │(indep)│
                   └──────┘ └────┘ └─────┘ └─────┘ └──────┘
                        │     │     │     │
                        ▼     ▼     ▼     ▼
                   Scenario adapters (PowerShell, spray, persistence)
                        │     │     │     │
                        ▼     ▼     ▼     ▼
              Evidence ─ Audit ─ Privacy(future) ─ ES store
```

- Orchestrator = E.1 synchronous state machine; owns lifecycle authority.
- Scenario adapters = E.4 plugins: `detection_query`, `read_tools`, `policy_profile`, `verify_checks`.
- LLM = one reasoning component, untrusted, gated by policy at every action.
- Executor = simulated (ADR-013); Verifier = independent, deterministic.

---

**Gate: architecture E.1+E.4 recommended. Await explicit approval before Phase C (agent/tool/privacy/policy/state machine design).**