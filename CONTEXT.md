# Aegis — Domain Glossary

## Core Concepts

### Autonomous Operations Loop
The outer layer that continuously polls ES for alerts, prioritizes by `severity × age × asset_criticality` (multiplicative scoring), and feeds them into the single-alert investigate pipeline. Approval requests are queued; the loop continues investigating other alerts while waiting. Polling is interval-based (default 300s), configurable to continuous via `AEGIS_POLL_INTERVAL=0`. Sequential investigation (one alert at a time). Backpressure: slow down when model/ES overloaded.

### Single-Alert Investigation
The existing A1-A5 agent pipeline + policy engine + execute/verify. This is the *inner core* that processes one alert end-to-end. Unchanged — the autonomous loop feeds it.

### AI Proposes, Deterministic Controls Dispose
Core safety principle. LLM agents reason and recommend. Policy engine, executor, and verifier are deterministic. LLM never mutates incident state or executes actions.

### Approval Queue
In autonomous mode, when an agent wants to take action, the request is queued and the loop continues investigating other alerts. Operator approves/rejects asynchronously.

### Evidence
Telemetry events (Sysmon, winlogbeat) collected during investigation. Typed, graphed, contradiction-detected. Wrapped as data blocks — LLM never sees raw telemetry directly.

### Privacy Gateway
Secrets/PII detected and redacted before AI views. Decisions audited. Emergency controls operate without the LLM.

### Policy Engine
Deterministic function that evaluates (action, facts) → decision (ALLOW/APPROVE/DENY). No LLM involvement.

### Executor (Simulated)
Currently simulated. Contract: receive action → execute → report result. Designed for real EDR swap later (CrowdStrike, Microsoft Defender). Not a portfolio priority — the contract proves the architecture.

### Verifier (Simulated)
Currently simulated. Contract: receive action + result → verify success → report. Read-only. Paired with executor; not worth implementing real without real executor.

### Console UI
Jinja2 template-based dashboard (exists). Shows incident list, detail pages, approve/deny actions, audit view, graph view. Will be extended for autonomous operations: status panel, approval queue, priority queue visualization.

### Agents (A1-A5)
- A1: Triage — initial alert classification
- A2: Evidence — fetch and correlate telemetry
- A3: Correlation — cross-incident relationships
- A4: ATT&CK Mapping — MITRE ATT&CK technique mapping
- A5: Recommendations — response recommendations

### Incident State Machine
TRIAGING → INVESTIGATING → CORRELATING → ASSESSING → RESPONSE_PLANNED → AUTHORIZED → EXECUTING → VERIFYING → RESOLVED/REOPENED/ESCALATED/FAILED/CANCELLED

### Audit Trail
Every action, decision, and data access recorded. Hash-chained for integrity. Model + prompt version tracked per incident.

### Evidence Graph
Typed edges between evidence records, incidents, and ATT&CK techniques. Built at collection time (WP-C). Supports contradiction detection: two records conflicting on the same entity get `contradicts` field populated. Cross-incident IOC edges link related incidents sharing indicators.

### ATT&CK Mapping
MITRE ATT&CK technique mapping from agent A4/A5 results. 697 techniques in local STIX data. Mapping validation: fabricated evidence references stripped, confidence thresholds enforced. Versioned via `ATTACK_DATA_VERSION`.

### Threat Intelligence Chain
Multi-provider TI lookup: local STIX store, AbuseIPDB, VirusTotal, OTX, NVD. Chained: local first, live providers opt-in via `TI_PROVIDERS` env. Each provider has rate limits and API key management.

### Tool Registry
Authorization gates for agent tool access. Each tool has: name, description, JSON schema, budget limits (calls, tokens), rate limits. Registry enforces: agents can only call tools they're authorized for. Emergency controls can revoke tools at runtime.

### Tamper Protection
Hash chain on audit events + evidence records. Each record's hash includes the previous record's hash. Verification: `verify_chain()` checks entire sequence. Evidence integrity: per-record content hashes verified post-pipeline.
