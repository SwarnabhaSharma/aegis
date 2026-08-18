# Aegis — Phase C: Security & Agent Design

Per doc §31-C. Covers G (agent model), H (tool model), I (privacy model), J (policy model), K (incident state machine) + emergency controls. **Stops for review.**

---

## G. Agent Model

**5 LLM reasoning agents + 2 deterministic services.** All reasoning output is *proposal*; deterministic controls own authority (ADR-005/006/009).

### G.1 Agent table

| # | Agent | Input | Output | Tools (scope) | Data permissions |
|---|---|---|---|---|---|
| A1 | Triage | Alert + alert metadata | Classification, severity, dismiss/investigate, required investigation | none | Alert metadata → incident state |
| A2 | Investigation | Incident + triage plan | Evidence set, timeline, open questions | read tools (all) | Telemetry → evidence |
| A3 | Correlation | Evidence set | Event links, attack chain, affected assets | read tools (correlation subset) | Evidence → correlation records |
| A4 | Threat Analysis | IOC/evidence | Assessment, ATT&CK mapping, confidence | TI lookups | IOC/evidence → assessment |
| A5 | Response Planner | Evidence + policies | Response plan (actions, rationale, risk, expected outcome) | read policy | Evidence/policy → plan |
| D1 | Response Executor | Approved plan | Action result | gated response tools | approved context → result |
| D2 | Verifier | Action + post-state | Verified/not, reopen/escalate | verify tools | post-action telemetry → verification state |

### G.2 Agent interaction rules

- **No direct agent→agent calls.** Handoff only via incident store (evidence, timeline, assessment, plan records). Kills agent-loop risk (D-006).
- **Sequential pipeline**: A1 → A2 → A3 → A4 → A5 → (D1) → D2. Orchestrator enforces order per state machine; agents do not self-trigger.
- **Budgets** (D-006/007): per-agent step budget (e.g. 20 steps), per-incident tool-call quota, per-phase time budget. Exceed → incident escalates to human.
- **Permissions**: immutable per-agent tool/permission table. Agent cannot request scope change (D-004).

### G.3 Reasoning output contract

Every agent emits JSON:
```json
{
  "summary": "...",
  "confidence": 0.0,
  "evidence_ids": ["ev_123"],
  "hypotheses": [...],
  "recommendations": [...]
}
```
- Every conclusion must reference `evidence_ids` that exist in store (D-008) — no bare "model thinks so".
- LLM output parsed with fallback; malformed → fail-safe (retry once, then degrade).

---

## H. Tool Model

### H.1 Tool contract (all tools)

```json
{
  "name": "isolate_host",
  "schema": { "input": {...typed...}, "output": {...typed...} },
  "risk_class": "READ | LOW | MEDIUM | HIGH",
  "reversible": true,
  "allowed_agents": ["D1"],
  "timeout_ms": 30000,
  "retry": "none | once | idempotent",
  "idempotent": true,
  "rate_limit_per_incident": 5,
  "audit": true
}
```

### H.2 Tool inventory

**Read tools** (allowed A2, A3, A4):
```text
search_events(query) -> events
get_process_tree(host) -> process tree
get_network_connections(host) -> conns
get_authentication_events(user|host) -> auth events
get_host_details(host) -> details
get_file_activity(host) -> file events
lookup_ip(ip) / lookup_domain(d) / lookup_hash(h) -> TI intel
get_policy(incident_type) -> applicable policy
```

**Response tools** (allowed D1 only, risk-classed):
```text
isolate_host(host)         HIGH  reversible  idempotent
disable_account(user)      HIGH  reversible  idempotent
terminate_process(host,pid)MEDIUM reversible  idempotent
block_indicator(indicator) MEDIUM reversible  idempotent
remove_persistence(host)   HIGH  partially   idempotent
```

**Verify tools** (allowed D2 only):
```text
verify_host_isolated(host) -> state
verify_process_terminated(host,pid) -> state
verify_indicator_blocked(indicator) -> state
verify_persistence_removed(host) -> state
```

### H.3 Tool classes

| Class | Definition | Execution |
|---|---|---|
| READ | read-only, no state change | AI may call directly (bucket 1) |
| LOW | reversible, low impact | policy auto-approve if conditions met |
| MEDIUM | reversible, moderate impact | policy + conditions |
| HIGH | sensitive/partially irreversible | policy + human approval (bucket 3) |

### H.4 Safe failure (doc §16)

- Every response tool has: risk, reversibility, expected result, timeout, verify method, rollback (where possible), failure→REOPEN+escalate.
- Executor never trusts HTTP 200 — D2 verifies actual state (ADR-009).
- Simulated executor (ADR-013) for now; contract identical for real backend.

---

## I. Privacy Model

**Deferred per ADR-003.** Design stance so it layers in later without rework:

- Every evidence record carries field metadata + classification tag (PII/secret/normal/unknown) from ingestion — classification is data, not enforcement.
- View layer (what an agent/operator sees) is a separate concern from store; privacy gateway inserts at the view boundary in Phase 8.
- Audit captures "data requested / released / withheld" fields now (schema reserved), so Phase 8 just fills enforcement.

No further privacy work in current phase. Revisit at Phase 8 gate.

---

## J. Policy Model

### J.1 Policy document

```yaml
action: isolate_host
version: "1.3"
conditions:
  confidence: ">= 0.90"
  asset_criticality: "!= critical"
  evidence_count: ">= 3"
  threat_mapping: "present"
approval_required: false
risk_class: HIGH
```

### J.2 Policy engine rules

- **Deterministic** (ADR-006): pure function `(action, incident_facts, policy) -> ALLOW | APPROVE | DENY`. No LLM in evaluation.
- **Versioned**: every decision records policy version (reproducibility).
- **Precedence**: most-specific policy wins; conflict → DENY (fail-safe) + audit alert.
- **Emergency override**: human can force ALLOW or DENY, logged as override (distinct audit event).
- **Dry-run mode**: evaluate without executing; produces would-be decision + reasons.
- **Approval flow**: DENY-with-approval → approval request → operator approve/deny (single operator now, ADR-014).
- **Testable**: policy suite = unit tests per policy; table of (facts → expected decision).

### J.3 Autonomy mapping (from Phase A buckets)

| Bucket | Policy result | Example |
|---|---|---|
| Fully autonomous | READ tools + LOW actions auto-ALLOW | evidence collection |
| Policy-authorized | conditions met → ALLOW | non-critical isolate, conf≥.9, ≥3 evidence |
| Human-approved | HIGH risk / critical asset / ambiguous | critical isolate, disable_account |
| Forbidden | hard DENY, always | privilege escalation, data beyond scope |

---

## K. Incident State Machine

### K.1 States

```
NEW → TRIAGING → INVESTIGATING → CORRELATING → ASSESSING
  → RESPONSE_PLANNED → AWAITING_APPROVAL → AUTHORIZED
  → EXECUTING → VERIFYING → RESOLVED
                         ↘ REOPENED ↻ (back to INVESTIGATING)
                         ↘ ESCALATED
  → FAILED (any state, safe failure)
```

### K.2 Transition table (actor → allowed)

| From | To | Actor | Condition |
|---|---|---|---|
| NEW | TRIAGING | orchestrator | alert ingested |
| TRIAGING | INVESTIGATING | orchestrator | triage: investigate (else → RESOLVED as dismissed) |
| TRIAGING | RESOLVED | orchestrator | triage: false positive, logged |
| INVESTIGATING | CORRELATING | orchestrator | evidence collected |
| CORRELATING | ASSESSING | orchestrator | correlation done |
| ASSESSING | RESPONSE_PLANNED | orchestrator | assessment + plan ready |
| RESPONSE_PLANNED | AWAITING_APPROVAL | orchestrator | plan needs approval |
| RESPONSE_PLANNED | AUTHORIZED | orchestrator | policy auto-ALLOW (no approval needed) |
| AWAITING_APPROVAL | AUTHORIZED | **operator** | approved |
| AWAITING_APPROVAL | RESOLVED | **operator** | denied/closed |
| AUTHORIZED | EXECUTING | orchestrator | executor starts |
| EXECUTING | VERIFYING | orchestrator | actions done |
| VERIFYING | RESOLVED | orchestrator | verification passed |
| VERIFYING | REOPENED | orchestrator | verification failed (or operator reopen) |
| REOPENED | INVESTIGATING | orchestrator | new evidence loop |
| any | ESCALATED | orchestrator | human | budget exceeded / timeout / uncertain / verify-fail-2x |
| any | FAILED | orchestrator | unrecoverable error, safe stop |
| any | (pause) | **operator** | emergency: halt autonomy |

### K.3 Rules

- **Authority**: state mutation only by orchestrator or explicit operator action. LLM agents cannot mutate state directly (ADR-005) — they write evidence/plan/assessment records, not lifecycle state.
- **Timeouts**: per-state timeout; on timeout → auto-ESCALATED (fail-safe, not silent continue).
- **Idempotency**: transition re-apply is no-op; concurrent transitions serialized per incident (single-writer).
- **Recovery**: FAILED/ESCALATED incidents are human-owned; no autonomous re-trigger.
- **Audit**: every transition → audit event (from/to/actor/condition/evidence refs).

---

## Emergency controls (doc §17)

Operator-only (independent of LLM), scope selectable:

| Control | Global | Per-agent | Per-tool | Per-incident |
|---|---|---|---|---|
| Pause autonomous ops | ✅ | ✅ | ✅ | ✅ |
| Disable agent | | ✅ | | ✅ |
| Revoke tool permission | | | ✅ | |
| Require approval for all responses | ✅ | ✅ | | ✅ |
| Disable specific response action | | | ✅ | |
| Terminate active workflow | ✅ | ✅ | ✅ | ✅ |
| Safe mode (read-only, no actions) | ✅ | | | |
| Restore normal operation | ✅ | ✅ | ✅ | ✅ |

All emergency actions: logged as operator override audit events, take effect immediately, persist across restarts until reverted.

---

**Gate: Phase C design complete (5 agents + 2 deterministic services, tool contracts, deferred privacy, deterministic policy, state machine + emergency controls). Await review before Phase D (data model, technology, roadmap, vertical slice).**