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
| Minimum necessary data & authority | PRESENT | Authority minimal; field minimization via AI_VISIBLE_FIELDS per tool + task_view per agent (`privacy/__init__.py`, `gateway.py`) |
| AI authority boundary (3.2) | PRESENT | Agents propose-only; state machine rejects agent actor |
| AI vs deterministic split (3.3) | PRESENT | LLM confined to `agents/reasoning.py`; D1/D2 deterministic |
| Evidence integrity (3.4) | PRESENT | Degrade-not-fabricate ✅; evidence_ids validated + fabricated stripped/flagged (`bb18bd2`, #6 closed); provenance flag on Evidence (`815f89f`) |
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
| Verification Agent (D2) | PRESENT | all 5 verify methods reachable via `execute_and_verify()` (`815f89f`) |

## §8 Tool architecture

| Item | Status | Notes |
|---|---|---|
| search_events / get_process_tree / get_network_connections | PRESENT | ES + in-memory backends |
| get_file_activity | PRESENT | Sysmon 11; ES + in-memory (`81a600f`) |
| get_authentication_events / get_host_details | PRESENT | Security-channel logons + per-host aggregation (`81a600f`) |
| lookup_ip / domain / hash | PRESENT | rich TI shape |
| get_threat_intelligence | PRESENT | aggregate TI tool (`815f89f`) |
| isolate_host | PRESENT | idempotent, simulated backend |
| terminate_process / block_indicator / disable_account / remove_persistence | PRESENT | all 4 tools built + verified + ActionSpec'd (`81a600f`, `57e221f`) |
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
| Data classification engine | PRESENT | 6-level taxonomy: normal/internal/pii/confidential/secret/restricted (`815f89f`) |
| Redaction | PRESENT (minimal) | [REDACTED:kind] masking before AI-visible views (`318f3e1`) |
| Tokenization | PRESENT | reversible per-incident vault; analyst reveal (`6735668`) |
| Field-level access control | PRESENT (minimal) | per-tool allowlist + RoleView AI/analyst split + task-based minimization profiles (`6735668`) |
| Contextual minimization | PRESENT | task-based event profiles per agent + prompt-level redaction via gateway (`privacy/__init__.py`, `gateway.py`) |
| Four representations (raw/filtered/AI-visible/analyst-visible) | PRESENT | raw/AI-visible via AI_VISIBLE_FIELDS/analyst via TokenVault/gateway (`gateway.py`, analyst-view endpoint) |
| Auditable privacy decisions ("why received / why withheld") | PRESENT | privacy_redaction + privacy_withheld audit events with withheld_keys/task_filtered (`gateway.py`) |
| Dimension analysis (field/role/agent/task/incident/asset/context) | ABSENT | documented design question, Phase 8 |

## §11 Agent data/action permissions

| Requirement | Status | Notes |
|---|---|---|
| Static per-agent tool sets | PRESENT | registry allowed_agents |
| Conditional dimensions | PRESENT | state/confidence/criticality/time/environment gates via PermissionContext (`57e221f`) |

## §13 Policy engine

| Requirement | Status | Notes |
|---|---|---|
| Pure evaluate() ALLOW/APPROVE/DENY | PRESENT | no LLM involvement |
| Versioned decisions | PRESENT | policy_version on every decision |
| Conflict → DENY fail-safe | PRESENT | simplified agree-or-DENY |
| Most-specific precedence | PRESENT | condition-count specificity, version tiebreak, generalized fallback (`dcadd29`) |
| Emergency override | PRESENT | engine fn + `POST /incidents/{id}/override` endpoint (`57e221f`) |
| Dry-run mode | PRESENT | flag on record |
| YAML policy files | ABSENT | Python dicts by choice (lazy pick #3, revisit if ops demand) |

## §14 Evidence-driven AI

| Requirement | Status | Notes |
|---|---|---|
| Provenance/timestamps/source/method/raw-ref/classification | PRESENT | Evidence model |
| Confidence-per-evidence | PRESENT | Evidence.confidence (graph edges carry it too) (`a64ccf2`) |
| Relationships / evidence graph | PRESENT | full typed graph, ADR-021 (`a64ccf2`) |
| Contradictory evidence handling | PRESENT | contradicts field populated by `_detect_contradictions()` (`57e221f`); A3 emission logic in pipeline |
| Evidence expiration | PRESENT | valid_until checked by validator (a64ccf2) |
| Conclusions linked to existing evidence (D-008 enforcement) | PRESENT | validate_evidence strips fabricated refs (`bb18bd2`) |

## §15 Adversarial security

| Threat | Status | Notes |
|---|---|---|
| Prompt injection via telemetry | PRESENT | untrusted_data wrapping + escaping + system rule + heuristic detector (`bb18bd2`); adversarial corpus expanded with indirect/delimiter-forgery/TI-poisoning scenarios (`test_adversarial.py`) |
| Indirect prompt injection | PRESENT | same mechanism covers TI/tool-result paths; adversarial tests for TI injection + correlation text poisoning (`test_adversarial.py`) |
| Tool abuse | PRESENT | registry authorization |
| Privilege escalation | PRESENT | static permission sets |
| Data exfiltration | PRESENT | tool scope bounds reads + field-level minimization via AI_VISIBLE_FIELDS + task_view (`privacy/__init__.py`) |
| Malicious threat intelligence | PRESENT | provider framework + guards shipped (f616075); responses enter prompts via untrusted wrapping; adversarial TI injection tests (`test_adversarial.py`) |
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
| Structured ActionSpec (expected result/rollback/timeout/failure→escalation) for all actions | PRESENT | all tools (read + response) spec'd (`57e221f`) |
| "HTTP 200 ≠ success" | PRESENT | D2 independent verification |

## §17 Human override & emergency controls

| Requirement | Status | Notes |
|---|---|---|
| Operator approve/deny | PRESENT | API endpoint + state machine gate |
| Policy override fn | PRESENT | engine fn + require-approval-all + `POST /incidents/{id}/override` (`57e221f`) |
| Pause autonomy | PRESENT | ControlState.pause + pipeline halt (`81a600f`) |
| Disable individual agents | PRESENT | disabled_agents -> fail-safe stop at stage (`81a600f`) |
| Revoke tool permissions at runtime | PRESENT | revoked_tools checked in registry.call (`81a600f`) |
| Require-approval-for-all mode | PRESENT | flips ALLOW->APPROVE pre-transition (`81a600f`) |
| Terminate active workflow | PRESENT | pause blocks new runs; mid-run cancellation via `cancelled_incidents` flag checked in pipeline + agentic loops; `CANCELLED` state + operator transitions |
| Safe mode + restore | PRESENT | enter_safe_mode/restore_normal (`81a600f`) |

## §18 Observability & audit

| Requirement | Status | Notes |
|---|---|---|
| Transitions + timeline records | PRESENT | incidents-steps index |
| Policy version capture | PRESENT | on every decision |
| audit-* index + AuditEvent entity | PRESENT | `audit.py` AuditRecorder + aegis-dev-audit sink (`bb18bd2`, #4 closed) |
| Full capture list (model/version, prompt id, data requested/released/withheld, tool requested, authz decision, retries) | PRESENT | all fields captured in pipeline_stage + tool_call audit events (`2ace218`, `815f89f`) |
| AgentRun / ToolCall persisted records | PRESENT | record:agentrun + record:toolcall via add_record (`bb18bd2`, #5 closed) |
| Tamper protection (hash chain) | PRESENT | SHA-256 chain on AuditEvents + Evidence records; `verify_chain()` + `verify_evidence_integrity()`; `GET /incidents/{id}/integrity` endpoint |

## §19 Data model entities

| Entity | Status |
|---|---|
| Incident / Alert / TimelineEvent / Evidence / Transition | PRESENT |
| Asset / Identity / Indicator | PRESENT | record-kind entities; criticality from records, map = fallback (90b1d27, #9 retired) |
| AgentRun / ToolCall / PolicyDecision-persisted / Approval / ResponseAction-persisted / Verification-persisted | PRESENT | all record kinds persisted (`57e221f`) |
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
| Audit-event generation asserted in tests | PRESENT | recorder unit-tested + `test_slice_generates_audit_events` (`57e221f`) |

## §27 First vertical slice

| Requirement | Status | Notes |
|---|---|---|
| PowerShell slice end-to-end | PRESENT | CLI + API + tests; real telemetry + real Ornith verified |
| Privacy filtering step in slice flow | PRESENT | classification at collection + redaction before AI views (`318f3e1`) |
| Executor realism | DEFERRED (ADR-013) | simulated until real backend phase |

## §28 UX console

| View | Status |
|---|---|
| Incident queue + incident detail + audit replay | PRESENT | server-rendered Jinja2 + dark CSS (`081ac79`) |
| Privacy view + response view with tab navigation | PRESENT | data requested/released/withheld, policy decisions, verification (`798eb6a`) |

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
| Tier 1 quick wins | persist Approval/ResponseAction records; contradicts edges; time/env permission dims; override endpoint; audit test; read-tool ActionSpecs | 19, 14, 11, 17, 26, 16, 8 | **DONE 57e221f** |
| Tier 2 feature completions | provenance flag; full D2 verify reachability; aggregate TI tool; richer classification; override endpoint; capture list | 3.4, 7, 8, 10, 17, 18 | **DONE 815f89f** |
| Privacy gateway | task_view wired; AI_VISIBLE_FIELDS expanded; gateway.py created; TokenVault integrated; withheld_keys audit; analyst-view + reveal endpoints | 3, 10, 15 | **DONE gateway.py** |
| Tier 3 adversarial + tamper | adversarial corpus (test_adversarial.py); Evidence hash field; verify_evidence_integrity; integrity API endpoint; slice wiring | 15, 18 | **DONE test_adversarial.py** |
| Mid-run cancellation | cancelled_incidents flag; pipeline + agentic loop checks; CANCELLED state; operator transitions; cancel/uncancel endpoints | 17 | **DONE test_midrun_cancel.py** |

Deferred-by-decision (not backlog): executor realism (ADR-013), RAG (ADR-007).

---

*Update rule: flip token + commit hash per closed row. Keep this file honest — a wrong PRESENT here is a lie an interviewer will find.*
