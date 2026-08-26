# Aegis Gap Audit — Living Tracker

- **Source of truth**: `D:\Resume\Aegis — Master Project Architecture Prompt — Polished.md` (§3–§29)
- **Audit date**: 2026-08-23 (baseline `c53d00b`; T1-T4 done; **partial-completion WPs: A `90b1d27`, C `a64ccf2`, G `f616075`, B `dcadd29`, E `c9fa99b`, D `2ace218`, F `6735668`, H `5dbece7`**)
- **Legend**:
  - `PRESENT` — built, meets spec
  - `PARTIAL` — exists, below spec (notes name the delta)
  - `ABSENT` — required by spec, not built
  - `DEFERRED (ADR-nnn)` — deliberate decision, NOT backlog; only ADR-backed items may use this
- **Update rule**: when an item closes, flip the token, append commit hash. `grep ABSENT docs/gap-audit.md` = true backlog; `grep DEFERRED` = intentional non-goals.

---

## §3 Core Design Principles

| Requirement | Status | Where / Notes |
|---|---|---|
| Minimum necessary data & authority | PARTIAL | Authority minimal (`state_machine.py`, registry); agents see full context dict — no field minimization (blocked on privacy §10) |
| AI authority boundary (3.2) | PRESENT | Agents propose-only; state machine rejects agent actor |
| AI vs deterministic split (3.3) | PRESENT | LLM confined to `agents/reasoning.py`; D1/D2 deterministic |
| Evidence integrity (3.4) | PARTIAL | Degrade-not-fabricate ✅; evidence_ids validated + fabricated stripped/flagged (`bb18bd2`, #6 closed); synthetic-vs-real provenance flag missing on Evidence |
| Fail-safe operation (3.5) | PRESENT | Degrade→ESCALATED, budget→stop, verify-fail→REOPEN→ESCALATED |

## §4 Autonomy model

| Requirement | Status | Where |
|---|---|---|
| Four buckets (auto / policy-authorized / human-approved / forbidden) | PRESENT | `policies/engine.py`, state machine |

## §5 RAG position

| Requirement | Status | Notes |
|---|---|---|
| No RAG unless justified | DEFERRED (ADR-007) | Not needed for current design |

## §6 Lifecycle / §12 State machine

| Requirement | Status | Where |
|---|---|---|
| Full lifecycle + actor authority + fail-safes | PRESENT | `orchestrator/state_machine.py`, `engine.py`; transitions recorded + timeline mirrors |

## §7 Agent architecture

| Agent | Status | Notes |
|---|---|---|
| A1 Triage | PRESENT | agentic-capable |
| A2 Investigation | PRESENT | agentic over real tools |
| A3 Correlation | PRESENT | shared-IOC correlation live since evidence persistence |
| A4 Threat Analysis | PRESENT | matrix-backed ATT&CK (697 techniques, STIX ingestion); structured attack_techniques output; validation gate (`b7d8120`) |
| A5 Response Planner | PRESENT | fetches policy itself via registry |
| Response Agent (D1) | DEFERRED (ADR-013) | simulated executor until real backend phase |
| Verification Agent (D2) | PARTIAL | service exists; 3 of 4 verify methods unreachable (no producing action) (#11) |

## §8 Tool architecture

| Item | Status | Notes |
|---|---|---|
| search_events / get_process_tree / get_network_connections | PRESENT | ES + in-memory backends |
| get_file_activity | PRESENT | Sysmon 11; ES + in-memory (`81a600f`) |
| get_authentication_events / get_host_details | PRESENT | Security-channel logons + per-host aggregation (`81a600f`) |
| lookup_ip / domain / hash | PRESENT | rich TI shape |
| get_threat_intelligence | ABSENT | aggregate intel tool |
| isolate_host | PRESENT | idempotent, simulated backend |
| terminate_process / block_indicator / disable_account / remove_persistence | PARTIAL | terminate/block/remove built + verified (`81a600f`); disable_account pending (needs Identity entity) |
| verify_host_isolated / process_terminated / indicator_blocked / persistence_removed | PRESENT | all reachable — executor produces state, verifier reads it (`81a600f`, #11 closed) |
| Typed input schema | PRESENT | loose dict types |
| Typed output schema | PRESENT | schema_out declared + shape-checked (`c9fa99b`) |
| Authorization + permitted agents | PRESENT | registry-enforced gate |
| Risk classification | PRESENT | READ/LOW/MEDIUM/HIGH |
| Audit logging per tool call | PRESENT | registry `.calls` capture + AuditRecorder (`bb18bd2`, #4 closed) |
| Timeout enforcement | PRESENT | thread-pool future per call (`c9fa99b`; hung-worker leak documented) |
| Retry behavior | PRESENT | retry=safe auto-retries once for idempotent tools (`c9fa99b`) |
| Rate limits | PRESENT | per-tool token bucket (`c9fa99b`) |
| Idempotency | PRESENT | executor dedupes by key |

## §9 Security authority model

| Requirement | Status | Notes |
|---|---|---|
| Registry + state machine + policy as controls | PRESENT | execution routed through registry gate (`81a600f`, #7 closed) |

## §10 Privacy architecture

| Requirement | Status | Notes |
|---|---|---|
| PII detection | PRESENT (minimal) | email/SSN regex (`318f3e1`) |
| Secret/credential detection | PRESENT (minimal) | credential kv / AWS keys / JWT / private-key headers (`318f3e1`) |
| Data classification engine | PARTIAL | normal/pii/secret levels on Evidence at collection; richer taxonomy pending |
| Redaction | PRESENT (minimal) | [REDACTED:kind] masking before AI-visible views (`318f3e1`) |
| Tokenization | PRESENT | reversible per-incident vault; analyst reveal (`6735668`) |
| Field-level access control | PRESENT (minimal) | per-tool allowlist + RoleView AI/analyst split + task-based minimization profiles (`6735668`) |
| Contextual minimization | PARTIAL | task-based event profiles per agent (6735668); prompt-level minimization pending |
| Four representations (raw/filtered/AI-visible/analyst-visible) | PARTIAL | raw/AI-visible/analyst distinct (`318f3e1`,`6735668`); filtered store snapshot pending |
| Auditable privacy decisions ("why received / why withheld") | PRESENT (minimal) | privacy_redaction audit events with where/kinds/reason (`318f3e1`) |
| Dimension analysis (field/role/agent/task/incident/asset/context) | ABSENT | documented design question, Phase 8 |

## §11 Agent data/action permissions

| Requirement | Status | Notes |
|---|---|---|
| Static per-agent tool sets | PRESENT | registry allowed_agents |
| Conditional dimensions | PARTIAL | state/confidence/criticality gates via PermissionContext (`dcadd29`); time/environment pending |

## §13 Policy engine

| Requirement | Status | Notes |
|---|---|---|
| Pure evaluate() ALLOW/APPROVE/DENY | PRESENT | no LLM involvement |
| Versioned decisions | PRESENT | policy_version on every decision |
| Conflict → DENY fail-safe | PRESENT | simplified agree-or-DENY |
| Most-specific precedence | PRESENT | condition-count specificity, version tiebreak, generalized fallback (`dcadd29`) |
| Emergency override | PARTIAL | engine fn exists; no API/control-surface endpoint |
| Dry-run mode | PRESENT | flag on record |
| YAML policy files | ABSENT | Python dicts by choice (lazy pick #3, revisit if ops demand) |

## §14 Evidence-driven AI

| Requirement | Status | Notes |
|---|---|---|
| Provenance/timestamps/source/method/raw-ref/classification | PRESENT | Evidence model |
| Confidence-per-evidence | PRESENT | Evidence.confidence (graph edges carry it too) (`a64ccf2`) |
| Relationships / evidence graph | PRESENT | full typed graph, ADR-021 (`a64ccf2`) |
| Contradictory evidence handling | PARTIAL | contradicts field + validator surfacing; A3 emission logic pending |
| Evidence expiration | PRESENT | valid_until checked by validator (a64ccf2) |
| Conclusions linked to existing evidence (D-008 enforcement) | PRESENT | validate_evidence strips fabricated refs (`bb18bd2`) |

## §15 Adversarial security

| Threat | Status | Notes |
|---|---|---|
| Prompt injection via telemetry | PARTIAL | untrusted_data wrapping + escaping + system rule + heuristic detector (`bb18bd2`); no adversarial eval corpus yet (T4 measures) |
| Indirect prompt injection | PARTIAL | same mechanism covers TI/tool-result paths; corpus measurement pending (T4) |
| Tool abuse | PRESENT | registry authorization |
| Privilege escalation | PRESENT | static permission sets |
| Data exfiltration | PARTIAL | tool scope bounds reads; no minimization layer |
| Malicious threat intelligence | PARTIAL | provider framework + guards shipped (f616075); responses enter prompts via untrusted wrapping; live-feed corpus scenarios pending |
| Agent loops | PRESENT | no agent→agent calls; budgets |
| Excessive tool calls | PRESENT | real budget accounting |
| Hallucinated evidence | PRESENT | validation strips + flags fabricated refs (`bb18bd2`, #6 closed) |
| False remediation | PRESENT | D2 verifies actual state |
| Verification manipulation | PRESENT | verifier separate deterministic service |

## §16 Response safety

| Requirement | Status | Notes |
|---|---|---|
| isolate_host full safety profile | PRESENT | ActionSpec on tool (`81a600f`) |
| terminate_process / block_indicator full safety profile | PRESENT | ActionSpec: expected/verify/rollback/failure (`81a600f`) |
| Structured ActionSpec (expected result/rollback/timeout/failure→escalation) for all actions | PARTIAL | response tools spec'd; timeout enforcement + read-tool specs pending |
| "HTTP 200 ≠ success" | PRESENT | D2 independent verification |

## §17 Human override & emergency controls

| Requirement | Status | Notes |
|---|---|---|
| Operator approve/deny | PRESENT | API endpoint + state machine gate |
| Policy override fn | PARTIAL | engine fn exists; require-approval-all + control endpoints shipped (`81a600f`); per-decision force-override endpoint pending |
| Pause autonomy | PRESENT | ControlState.pause + pipeline halt (`81a600f`) |
| Disable individual agents | PRESENT | disabled_agents -> fail-safe stop at stage (`81a600f`) |
| Revoke tool permissions at runtime | PRESENT | revoked_tools checked in registry.call (`81a600f`) |
| Require-approval-for-all mode | PRESENT | flips ALLOW->APPROVE pre-transition (`81a600f`) |
| Terminate active workflow | PARTIAL | pause covers new runs; mid-run cancellation pending (async execution) |
| Safe mode + restore | PRESENT | enter_safe_mode/restore_normal (`81a600f`) |

## §18 Observability & audit

| Requirement | Status | Notes |
|---|---|---|
| Transitions + timeline records | PRESENT | incidents-steps index |
| Policy version capture | PRESENT | on every decision |
| audit-* index + AuditEvent entity | PRESENT | `audit.py` AuditRecorder + aegis-dev-audit sink (`bb18bd2`, #4 closed) |
| Full capture list (model/version, prompt id, data requested/released/withheld, tool requested, authz decision, retries) | PARTIAL | pipeline stages/tool calls/policy/injection/validation captured; data-requested/released/withheld + retries captured (2ace218); remaining: §10) |
| AgentRun / ToolCall persisted records | PRESENT | record:agentrun + record:toolcall via add_record (`bb18bd2`, #5 closed) |
| Tamper protection (hash chain) | ABSENT | post-#4 layer |

## §19 Data model entities

| Entity | Status |
|---|---|
| Incident / Alert / TimelineEvent / Evidence / Transition | PRESENT |
| Asset / Identity / Indicator | PRESENT | record-kind entities; criticality from records, map = fallback (90b1d27, #9 retired) |
| AgentRun / ToolCall / PolicyDecision-persisted / Approval / ResponseAction-persisted / Verification-persisted | PARTIAL | agentrun/toolcall/policy/verification persisted (`bb18bd2`); Approval + ResponseAction records still transient (#5 remainder) |
| AuditEvent | PRESENT | aegis-dev-audit sink (`bb18bd2`) |

Indices: `incidents-*` ✅ · `incident-steps-*` ✅ (evidence/transition/timeline/record:*) · `audit-*` ✅ (`bb18bd2`) · `telemetry-*` ✅ read-only.

## §20 Evaluation framework

| Requirement | Status | Notes |
|---|---|---|
| Reproducible corpus | PRESENT | evals/corpus.json: 6 labeled scenarios incl. telemetry-injection (`b19e0e5`); multi-stage corpus growth pending |
| Metrics runner | PRESENT | scripts/run_eval.py: precision/recall on investigate decision, unsafe-action count, injection detection, escalation + fabrication rates, mapping precision/recall -> json+md reports; live Ornith run: P=1.0 R=1.0 FP=0, mapping P=0.25 R=0.2 (`b7d8120`) |
| Deterministic-baseline comparison | ABSENT | optional stretch, remains open |

## §21 Versioning & reproducibility

| Requirement | Status | Notes |
|---|---|---|
| Policy version per incident decision | PRESENT | |
| Model version recording | PRESENT | manifest via LLMClient.model_tag (`bb18bd2`) |
| Prompt ids/versioning | PRESENT | PROMPT_VERSION const in reasoning.py (`bb18bd2`) |
| Tool schema versions | PRESENT | TOOL_SCHEMA_VERSION in registry (`bb18bd2`) |
| Per-incident version manifest block | PRESENT | record:manifest + slice result; includes attack_data_version (`b7d8120`) |

## §26 DoD discipline

| Requirement | Status | Notes |
|---|---|---|
| Tests incl. error/unauthorized cases per feature | PRESENT | 75 tests |
| Written per-feature DoD before implementation | ABSENT | process change, adopt from T1 onward |
| Audit-event generation asserted in tests | PARTIAL | recorder unit-tested; slice-level assertion pending |

## §27 First vertical slice

| Requirement | Status | Notes |
|---|---|---|
| PowerShell slice end-to-end | PRESENT | CLI + API + tests; real telemetry + real Ornith verified |
| Privacy filtering step in slice flow | PRESENT | classification at collection + redaction before AI views (`318f3e1`) |
| Executor realism | DEFERRED (ADR-013) | simulated until real backend phase |

## §28 UX console

| View | Status |
|---|---|
| All six views (queue/detail/privacy/agent activity/response/audit) | ABSENT — API is the foundation; Phase 10 |

## §29 Portfolio standard

| Requirement | Status | Notes |
|---|---|---|
| Documentation set (ADRs/assumptions/phases) | PRESENT | docs/ |
| README.md | PRESENT | quickstart/env/API/limitations (`c4df273`) |
| Architecture diagrams | PRESENT | docs/diagrams.md mermaid set (`c4df273`) |
| Threat model document | PRESENT | docs/threat-model.md assets/threats/mitigations/residuals (`c4df273`) |
| CI pipeline | PRESENT | GitHub Actions ruff+pytest (`b19e0e5`) |
| Packaged demo scenarios + reproducible evaluation | PRESENT | run_slice.py modes + evals/ runner+reports (`b19e0e5`) |
| Limitations/trade-offs explained | PRESENT | README limitations section + threat-model residuals + gap-audit itself |

---

## Build tiers → sections closed

| Tier | Scope | Closes sections | Debt ids retired |
|---|---|---|---|
| T1 Security hardening | telemetry-as-untrusted defense; evidence_ids validation; audit pipeline (#4+#5); version manifest | §15, §14(D-008), §18, §19(partial), §21 | **DONE `bb18bd2`** — #4, #5, #6 closed (Approval/ResponseAction records + hash chain remain) |
| T2 Controls + tools | emergency controls; get_file_activity (+auth/host reads); response tools ↔ verifier seams; ActionSpec struct; executor-via-registry | §17, §8, §16, §9(#7), §7(#11) | **DONE `81a600f`** — #7, #8(core), #11 closed (disable_account + timeout enforcement remain) |
| T3 Minimal privacy layer | detect→classify→AI-visible allowlist per agent/task→logged decisions | §10(minimal), §27 privacy step | **DONE `318f3e1`** — #9 (asset map) remains, folds into T4 context work |
| T4 Eval + portfolio | corpus + metrics runner; README; diagrams; threat model; CI | §20, §26, §28(foundation), §29 | **DONE `b19e0e5`+`c4df273`** — #12 closed (console UI views remain §28 backlog) |
| WP-A entities | Asset/Identity records; store-based criticality; disable_account+verify (#9) | 19, 11(criticality) | **DONE 90b1d27** |
| WP-C evidence graph | full typed graph, ADR-021; confidence/expiry/contradiction; A3 subgraph | 14 | **DONE a64ccf2** |
| WP-G TI framework | N-provider chain + AbuseIPDB/VT/OTX/NVD; guards (private-range/cache/rate-limit/degrade); lookup_cve | 15, 8(intel) | **DONE f616075** |
| WP-B precedence+permissions | most-specific-wins; PermissionContext gates (state/confidence/criticality) | 13, 11 | **DONE dcadd29** |
| WP-E contract mechanics | timeout enforcement; rate limits; retry=safe; schema_out; read ActionSpecs | 8, 16 | **DONE c9fa99b** |
| WP-D audit completion | hash-chain tamper evidence; data requested/released/withheld; retry counts | 18, 26 | **DONE 2ace218** |
| WP-F privacy depth | reversible tokenization vault; task minimization; RoleViews | 10 | **DONE 6735668** |
| WP-H eval expansion | corpus v2 multi-stage/incomplete; baseline comparator; audit assertion | 20, 26 | **DONE 5dbece7** |
| ATT&CK mapping | STIX matrix ingestion (697 techniques); structured A4 output; validation gate; MAPPED_TO edges; mapping precision/recall metrics | 14, 21, 20 | **DONE b7d8120** |

Deferred-by-decision (not backlog): privacy full gateway sequencing (ADR-003), executor realism (ADR-013), RAG (ADR-007).

---

*Update rule: flip token + commit hash per closed row. Keep this file honest — a wrong PRESENT here is a lie an interviewer will find.*
