# AEGIS — Elastic/Kibana Integration and Future SOC UI Prompt

## Context

Aegis is **already built**. The existing codebase contains the core platform functionality, including the implemented agent/orchestration workflows, investigation capabilities, threat-intelligence enrichment, evidence handling, incident workflows, policy/response mechanisms, and other existing components.

**Do not redesign or rebuild Aegis from scratch.**

Your role is to inspect the existing implementation first and then extend it through:

1. Elastic / Elasticsearch / Kibana integration
2. A complete end-to-end demonstration workflow
3. Clean API and data boundaries for a future custom Aegis SOC UI
4. Designing and, only after the integration is working and approved, implementing the custom UI

The existing codebase is the primary source of truth.

---

# 1. Your Role

Act as a:

- Senior Security Platform Architect
- Elastic Stack Engineer
- Backend Integration Engineer
- SOC Platform Engineer
- AI Systems Engineer
- Full-Stack Architect

Your responsibility is to **integrate and extend the existing Aegis platform**, not replace its architecture.

You must:

- Inspect before changing
- Reuse existing components wherever possible
- Minimize unnecessary refactoring
- Preserve existing architecture boundaries
- Identify genuine compatibility or security issues
- Propose the smallest reasonable change when changes are required

---

# 2. Primary Objective

The immediate objective is to make the existing Aegis platform work with the Elastic Stack and be demonstrable through Kibana.

The intended workflow is:

```text
Security Logs / Events
        ↓
Elasticsearch / Elastic Security
        ↓
Detection / Alert
        ↓
Existing Aegis Platform
        ↓
Existing Agents / Investigation Workflow
        ↓
Threat Intelligence Enrichment
        ↓
Evidence Collection and Correlation
        ↓
Assessment
        ↓
Policy-Controlled Response
        ↓
Verification
        ↓
Aegis Results Stored / Exposed
        ↓
Elasticsearch
        ↓
Kibana Visualization
```

The final integration should demonstrate that:

> **Elastic/Kibana provides SIEM-style visibility and security event exploration, while Aegis performs investigation, enrichment, reasoning, orchestration, and controlled response operations.**

---

# 3. Critical Architectural Principle

Aegis must remain an **independent platform**.

Do not turn Aegis into a Kibana plugin unless there is a compelling technical reason that is explicitly discussed and approved.

The intended architecture is:

```text
                 ┌─────────────────────┐
                 │ Elastic / Kibana    │
                 │ Logs / Alerts       │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │       AEGIS         │
                 │ Existing Core       │
                 │ Agents              │
                 │ Investigation       │
                 │ Threat Intel        │
                 │ Evidence            │
                 │ Policy / Response   │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Elasticsearch       │
                 │ Aegis Results       │
                 └──────────┬──────────┘
                            │
                            ▼
                         Kibana
```

Aegis business logic must remain independent of Kibana.

Long-term:

```text
                         AEGIS CORE
                             │
                     API / Integration Layer
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
        Elastic / Kibana          Future Aegis SOC UI
```

---

# 4. FIRST TASK — Inspect the Existing Aegis Codebase

Before making architectural decisions or implementing changes:

1. Inspect the complete repository.
2. Identify the current technology stack.
3. Understand the existing architecture.
4. Identify all existing Aegis services and components.
5. Identify existing APIs and entry points.
6. Identify the agent/orchestration architecture.
7. Identify investigation workflows.
8. Identify threat-intelligence integrations.
9. Identify incident, evidence, and entity models.
10. Identify existing state management.
11. Identify policy and response mechanisms.
12. Identify data stores.
13. Identify authentication and authorization mechanisms, if present.
14. Identify observability and logging mechanisms.
15. Identify existing Docker/infrastructure configuration.

Do not assume something is missing until the repository has been inspected.

---

# 5. Current State Report

After inspection, produce a concise report containing:

## A. Existing Architecture

Describe:

- Services
- Modules
- APIs
- Workers
- Agents
- Databases
- Message queues, if any
- Existing infrastructure

## B. Existing Aegis Capabilities

Identify what already exists for:

- Alert ingestion
- Incident creation
- Investigation
- Agent orchestration
- Entity extraction
- Threat intelligence
- Evidence handling
- Correlation
- Assessment
- Policy evaluation
- Response
- Verification
- Audit logging

## C. Existing Integration Points

Identify interfaces that can potentially be used for:

- Receiving Elastic alerts
- Querying Elasticsearch
- Triggering Aegis investigations
- Returning investigation results
- Storing Aegis data

## D. Integration Gaps

Identify only what is genuinely required for Elastic/Kibana integration.

For every gap, specify:

```text
Gap
Why it is required
Existing component that can be reused
Smallest proposed change
```

## E. Risks

Identify:

- Security risks
- Coupling risks
- Data-model mismatches
- Elastic compatibility concerns
- Operational complexity
- Potential vendor lock-in

Then STOP and wait for my approval before implementing major changes.

---

# 6. Scope Boundaries

## IN SCOPE

- Elastic / Elasticsearch integration
- Kibana visualization and workflows
- Connecting Elastic alerts/events to existing Aegis workflows
- Querying relevant Elastic event context during investigations
- Returning Aegis investigation results to Elasticsearch
- Creating Kibana dashboards, data views, saved searches, or other appropriate visualization mechanisms
- Demonstrating agents, enrichment, investigation, evidence, assessment, response, and verification
- Preparing Aegis APIs for future UI consumption
- Designing the future UI information architecture

## OUT OF SCOPE UNLESS NECESSARY

- Rebuilding existing Aegis agents
- Replacing the existing orchestration system
- Replacing existing threat-intelligence systems
- Redesigning the evidence model
- Rebuilding the policy engine
- Rewriting response mechanisms
- Large refactors for cosmetic reasons
- Building a complete Kibana clone
- Building the full custom Aegis UI before the Elastic integration is proven

If an existing component genuinely prevents integration, explain the problem and propose the smallest possible change.

Do not silently redesign working components.

---

# 7. Elastic Integration Investigation

Before choosing an integration approach, investigate the realistic options supported by the existing codebase and current Elastic capabilities.

Potential approaches may include:

- Polling Elasticsearch for alerts
- Elastic Security alert indices
- Elasticsearch APIs
- Webhook-based ingestion
- Connectors
- Event-driven integration
- Scheduled synchronization
- Custom middleware/adapter layer

Do not assume one approach is automatically best.

Compare viable approaches based on:

- Compatibility with the existing Aegis architecture
- Implementation complexity
- Reliability
- Latency
- Local development feasibility
- Docker compatibility
- Portfolio demonstration value
- Future scalability
- Security
- Vendor lock-in

Provide:

```text
Option
Architecture
Advantages
Disadvantages
Integration Complexity
Recommendation
```

Then recommend one approach and STOP for approval before locking the major integration architecture.

---

# 8. Preferred Integration Philosophy

The preferred design should resemble an adapter/integration layer:

```text
                    Elastic Adapter
                          │
                          ▼
                Normalized Alert/Event
                          │
                          ▼
                     Aegis API
                          │
                          ▼
                Existing Aegis Core
```

Aegis core components should not require knowledge of:

- Kibana UI structures
- Kibana-specific objects
- Elastic-specific dashboard concepts

Where possible, Elastic-specific formats should be translated at the integration boundary.

---

# 9. Alert and Event Flow

Design an end-to-end workflow using existing Aegis capabilities:

```text
Elastic Event
      ↓
Detection / Alert
      ↓
Elastic Integration Layer
      ↓
Normalize Alert Context
      ↓
Existing Aegis Entry Point
      ↓
Incident / Investigation Workflow
      ↓
Existing Agents
      ↓
Threat Intelligence
      ↓
Evidence
      ↓
Assessment
      ↓
Policy / Response
      ↓
Verification
      ↓
Aegis Result Exporter
      ↓
Elasticsearch
      ↓
Kibana
```

Reuse existing models and workflows wherever possible.

Do not duplicate incident logic inside the Elastic adapter.

---

# 10. Elasticsearch Data Strategy

Investigate and recommend how Aegis data should be stored or exposed through Elasticsearch.

Evaluate:

A. Enrich existing alert documents

B. Store Aegis investigation results in dedicated indices

C. Maintain references between Elastic alerts and Aegis incidents

D. Hybrid approach

The design should support:

- Alert ↔ Aegis incident traceability
- Investigation status
- Evidence references
- Assessment summaries
- Response status
- Audit references
- Timeline correlation

Avoid unnecessarily copying large raw datasets. Prefer references where appropriate.

---

# 11. Aegis Result Data Model

Do not blindly create a new schema if existing models already exist.

First inspect existing incident and investigation models.

Then determine the minimum representation required for Elasticsearch/Kibana.

The result should conceptually support:

- Aegis Incident ID
- Elastic Alert Reference
- Investigation Status
- Severity
- Assessment Summary
- Confidence / Assessment Metadata
- Evidence Summary
- Relevant Entities
- Threat Intelligence Summary
- Response State
- Verification State
- Timestamps
- Correlation ID

Clearly distinguish:

### Deterministic Facts
Observed logs and events.

### External Evidence
Threat intelligence and enrichment.

### Aegis/AI Assessment
Reasoned conclusions and hypotheses.

### Policy Decisions
Authorization outcomes.

### Response Results
Actions and verification.

Do not merge these into an opaque score.

---

# 12. ECS Compatibility

Investigate whether and where Elastic Common Schema (ECS) should be used.

Do not force the entire Aegis domain model into ECS if doing so would distort existing architecture.

Determine:

- Which event data should remain ECS-compatible
- Which Aegis-specific data requires custom fields
- How custom fields should be namespaced
- How Kibana queries and dashboards will access them

The goal is interoperability without forcing Aegis to become an Elastic-only product.

---

# 13. Querying Context from Elasticsearch

During an Aegis investigation, the existing platform may need relevant context from Elastic.

Design the integration so Aegis can retrieve, where needed:

- Events related to the same user
- Events related to the same source IP
- Events related to the same destination IP
- Events related to the same host
- Events within relevant time windows
- Events before and after the triggering alert

Do not make Elasticsearch querying logic spread across agents.

Prefer a dedicated boundary:

```text
Aegis Investigation
        │
        ▼
Elastic Context Tool
        │
        ▼
Elasticsearch
```

Existing agents should receive structured results rather than constructing arbitrary Elasticsearch queries without controls.

---

# 14. End-to-End Demonstration Scenario

Identify the best existing Aegis workflow for demonstrating the complete integration.

Prefer a scenario that can demonstrate:

```text
Security Event
      ↓
Elastic Detection
      ↓
Aegis Investigation
      ↓
Related Event Retrieval
      ↓
Threat Intel Enrichment
      ↓
Evidence Correlation
      ↓
Assessment
      ↓
Policy Evaluation
      ↓
Response Recommendation
      ↓
Approval or Safe Execution
      ↓
Verification
```

If multiple existing scenarios are available, recommend the best first demo and explain why.

Do not invent capabilities that do not exist.

---

# 15. Kibana Demonstration Goals

The Kibana integration should demonstrate the real system.

The ideal demo flow is:

1. Observe security logs/events in Kibana.
2. Show the suspicious event or alert.
3. Show how Aegis receives or retrieves the alert.
4. Show Aegis beginning investigation.
5. Show related events retrieved from Elastic.
6. Show threat-intelligence enrichment.
7. Show evidence collection and correlation.
8. Show the Aegis assessment while distinguishing facts, evidence, and AI inference.
9. Show the proposed response and policy decision.
10. Show human approval where required.
11. Show safe or real execution according to existing capabilities.
12. Show verification.
13. Show the end-to-end audit trail.

The goal is to demonstrate:

> **Aegis is not merely a chatbot attached to Kibana. It is an independent incident operations platform integrated with an existing SIEM workflow.**

---

# 16. How Aegis Should Appear in Kibana

Do not immediately attempt to build a complex Kibana plugin.

First investigate the simplest high-quality approach for making Aegis results usable inside Kibana.

Possible approaches include:

- Dedicated Aegis indices
- Kibana dashboards
- Discover views
- Saved searches
- Data views
- Drilldowns
- Links to Aegis APIs or future UI
- Embedded/custom visualizations if justified

Choose the simplest approach that demonstrates real integration.

Priority:

```text
Working Integration
        >
Demonstrable Workflow
        >
Useful Visualization
        >
Custom Kibana Extension
```

---

# 17. API-First Preparation for the Future Aegis UI

Although the custom UI should not be fully built before the integration works, the existing Aegis platform should expose clean interfaces that the future UI can consume.

Inspect existing APIs first.

Do not duplicate existing APIs.

Identify whether the existing platform already exposes:

- Incidents
- Investigations
- Evidence
- Entities
- Threat intelligence
- Actions
- Approvals
- Audit history
- Workflow state

If APIs are missing, propose minimal additions.

Desired future architecture:

```text
                    AEGIS CORE
                         │
                      API Layer
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
       Kibana       Future UI       Automation
```

The UI must consume Aegis APIs.

The UI must not directly depend on internal agent implementation details.

---

# 18. Future Custom Aegis SOC UI — Planning Scope

Do not build the full UI until the Elastic/Kibana integration milestone is functioning and approved.

However, while integrating, document UI requirements discovered from real usage.

The future Aegis SOC UI should be an **AI-native security operations console**, not a clone of Kibana.

Kibana should remain useful for:

- Raw log exploration
- Search
- Time-series analysis
- Existing Elastic Security workflows

The Aegis UI should focus on:

- Incidents
- Investigation progress
- Evidence
- Entity relationships
- AI assessment
- Threat intelligence
- Response workflows
- Approvals
- Verification
- Audit history

---


---

# 18A. Aegis UI Identity and Core UX Principles

The future Aegis UI must preserve the identity and operational philosophy of Aegis.

It must **not** become:

- A generic SOC dashboard
- A clone of Kibana
- A chatbot-first interface
- A collection of AI-generated summaries disconnected from evidence
- A UI that hides policy, authorization, privacy, or verification boundaries

Aegis should primarily present itself as an **AI-native security incident operations console**.

The UI should make the complete incident lifecycle understandable:

```text
Detection
   ↓
Investigation
   ↓
Evidence Collection
   ↓
Enrichment
   ↓
Assessment
   ↓
Policy Evaluation
   ↓
Authorization
   ↓
Human Approval (when required)
   ↓
Execution
   ↓
Verification
   ↓
Audit / Replay
```

The UI should prioritize:

- Operational clarity
- Evidence traceability
- Explainability
- Privacy visibility
- Agent transparency
- Response safety
- Auditability

Do not add screens merely because they are common in SOC products. Every UI component should correspond to a real Aegis capability or operational requirement.

---

# 18B. Clear Role Separation — Kibana vs Aegis UI

The final architecture must clearly separate the role of Kibana from the role of the custom Aegis UI.

## Kibana / Elastic Should Primarily Handle

- Raw log exploration
- Search
- Filtering
- Time-series analysis
- Security event exploration
- Existing Elastic Security workflows
- Broad SIEM visibility
- Dashboards over indexed telemetry

## Aegis UI Should Primarily Handle

- Incident operations
- Investigation lifecycle
- Evidence and provenance
- Agent activity
- AI assessment
- Threat-intelligence context
- Privacy and data-access decisions
- Policy and authorization state
- Response workflows
- Human approvals
- Execution status
- Independent verification
- Complete incident replay and audit history

The Aegis UI should complement Kibana rather than duplicate it.

Where useful, the UI may link back to Kibana for deep raw-log exploration.

---

# 18C. Core Aegis UI Views

The future UI should be planned around the following concepts, but only implement views supported by actual Aegis capabilities.

## 1. Incident Queue

Provide a clear operational queue showing:

- Incident ID
- Severity
- Current status
- Investigation state
- Affected assets or entities
- Trigger source
- Assessment/confidence metadata where meaningful
- Response state
- Verification state
- Ownership or workflow responsibility where supported

The queue should help an analyst quickly answer:

> What needs attention right now?

Avoid overloading the queue with every internal field.

---

## 2. Incident Detail

The incident detail page should be the central operational view.

It should make it easy to answer:

> What happened?

> What evidence supports the assessment?

> What did Aegis investigate?

> What did the agents do?

> What did the system infer?

> What was authorized?

> What action was taken?

> Was the result independently verified?

A conceptual structure:

```text
Incident Header
      │
      ├── Status
      ├── Severity
      ├── Summary
      └── Key Entities

Incident Timeline
      │
      ├── Trigger Event
      ├── Investigation Steps
      ├── Enrichment
      ├── Assessment
      ├── Policy / Authorization
      ├── Response
      └── Verification

Evidence
      │
      ├── Observed Facts
      ├── External Intelligence
      ├── Correlation
      └── Provenance

Agent Activity
      │
      ├── Agent Tasks
      ├── Tool Requests
      ├── Authorization
      └── Results

Response
      │
      ├── Recommendation
      ├── Policy Decision
      ├── Approval
      ├── Execution
      └── Verification
```

The exact implementation must follow the existing Aegis domain model.

---

## 3. Privacy and Data Access View

Privacy and data minimization should be visible, not hidden entirely inside backend logic.

Where the existing Aegis implementation supports these concepts, provide a view or panel showing:

- Data requested
- Data released
- Data withheld
- Data classification
- Access purpose
- Privacy filtering or redaction decisions
- Relevant authorization or policy decision

The goal is to make it possible to understand:

> What data did Aegis access, and why?

Do not expose sensitive raw data merely to demonstrate transparency.

The UI should show metadata and decisions according to authorization rules.

---

## 4. Agent Activity View

Aegis should expose meaningful agent activity without overwhelming users with internal chain-of-thought or unnecessary implementation details.

Show operationally useful information such as:

- Agent name or role
- Assigned task
- Current state
- Tool requested
- Authorization decision
- Tool result summary
- Failure or retry state
- Escalation
- Completion status

Do not expose hidden model reasoning.

The purpose is operational transparency:

> What did the system do?

not:

> Reveal private internal reasoning traces.

---

## 5. Response View

The response experience should clearly expose the complete control path:

```text
Recommended Action
        ↓
Supporting Evidence
        ↓
Assessment
        ↓
Policy Evaluation
        ↓
Authorization Decision
        ↓
Human Approval (if required)
        ↓
Execution
        ↓
Independent Verification
```

The UI must not allow users to bypass existing backend policy or authorization controls.

The frontend is a client of the authorization system, not the authority itself.

---

## 6. Incident Replay and Audit View

Incident replay should be treated as a first-class Aegis capability.

The user should eventually be able to reconstruct:

> Exactly what happened during the incident and why.

Where supported by the existing backend, the replay should show:

- Trigger event
- Timeline of investigation
- Evidence collected
- Evidence provenance
- Data accessed
- Agents involved
- Tool invocations
- Authorization decisions
- Policy decisions
- AI assessments
- Human approvals or rejections
- Response execution
- Verification results
- Errors, failures, and retries

The replay must distinguish:

- What was observed
- What was externally provided
- What Aegis inferred
- What policy decided
- What a human decided
- What action was executed
- What was independently verified

This should function as an operational and audit artifact, not merely a visual animation.

---

# 18D. Trust Boundary Visualization

The UI must expose important trust boundaries instead of hiding them.

Whenever possible, visually and structurally distinguish:

| Category | Meaning |
|---|---|
| Observed Fact | Directly observed telemetry or deterministic event data |
| Evidence | Supporting information with identifiable provenance |
| Threat Intelligence | External enrichment or reputation data |
| Aegis Assessment | AI/system inference or hypothesis |
| Policy Decision | Deterministic authorization or policy outcome |
| Human Decision | Analyst approval, rejection, or override |
| Execution Result | What the response system attempted or completed |
| Verification Result | Independently observed confirmation of the outcome |

Do not present all of these categories as equivalent truth.

The UI must help users understand:

- What is known
- What is inferred
- What is externally sourced
- What was authorized
- What was actually done
- What was independently verified

---

# 18E. Attack Chain and Entity Visualization

Do not add an attack graph merely for visual appeal.

First inspect whether the existing Aegis evidence and entity models support meaningful relationships.

Where supported, provide a way to visualize relationships such as:

```text
User
  │
Host
  │
Process
  │
Network Connection
  │
IP / Domain
  │
Alert
  │
Threat Intelligence
```

Potential uses include:

- Attack-chain reconstruction
- Entity correlation
- Evidence relationships
- Incident understanding

If the existing relationships are insufficient, do not force a graph.

A timeline or structured evidence view may be better.

---

# 18F. Chat Is Secondary, Not the Primary Interface

If Aegis includes or later adds conversational interaction, treat it as a supporting capability.

The primary interface should remain a security operations console centered around:

- Incidents
- Investigations
- Evidence
- Agents
- Policy
- Response
- Verification
- Auditability

Do not make the platform feel like a chatbot with a dashboard attached.

---


# 19. Future UI Information Architecture

After the Kibana integration is working, propose an information architecture.

Potential navigation:

```text
AEGIS
│
├── Overview
├── Alerts / Intake
├── Incidents
├── Investigations
├── Threat Intelligence
├── Response Center
├── Automation / Audit History
└── Settings
```

Do not assume all pages are required.

Base the UI on actual capabilities exposed by the existing Aegis platform.

Recommend:

### MVP Pages
Only the pages needed for a compelling portfolio demonstration.

### Phase 2 Pages
Additional features that add value.

### Future Features
Optional capabilities.

---

# 20. Incident Investigation UI Requirements

The incident page should eventually make it easy to answer:

> What happened?

> Why does Aegis think this matters?

> What evidence supports the assessment?

> What did Aegis investigate?

> What did the system recommend?

> What action was taken?

> Was it verified?

The page should conceptually contain:

```text
Incident Header
      │
      ├── Status
      ├── Severity
      ├── Summary
      └── Key Entities

Investigation Timeline
      │
      ├── Trigger Event
      ├── Investigation Steps
      ├── Enrichment
      ├── Assessment
      ├── Response
      └── Verification

Evidence
      │
      ├── Facts
      ├── External Intelligence
      └── Correlation

Assessment
      │
      ├── AI Inference
      ├── Confidence / Uncertainty
      └── Supporting Evidence

Response
      │
      ├── Recommendation
      ├── Policy Decision
      ├── Approval
      ├── Execution
      └── Verification
```

The final design must be based on the existing Aegis domain model.

---

# 21. Important UI Principle — Separate Facts from AI Reasoning

The UI must never make AI-generated conclusions appear identical to observed evidence.

Visually and structurally distinguish:

## Observed Facts
Example:

```text
423 failed authentication events occurred.
```

## Threat Intelligence
Example:

```text
An external threat-intelligence provider reported the IP.
```

## Aegis Assessment
Example:

```text
Aegis assesses the observed sequence as consistent with a credential attack.
```

## Policy Decision
Example:

```text
Response requires analyst approval.
```

This distinction is important for explainability and trust.

---

# 22. UI Technology Selection

Do not select the frontend stack blindly.

When the UI implementation phase begins, inspect the existing technology stack.

Prefer reuse where possible.

If a new frontend is needed, compare realistic options.

A possible modern stack may include:

- Next.js
- React
- TypeScript
- Tailwind CSS
- shadcn/ui
- TanStack Query
- TanStack Table
- Recharts
- React Flow

However, these are suggestions, not mandatory requirements.

Evaluate:

- Compatibility with the existing Aegis stack
- Development speed
- Portfolio quality
- Maintainability
- API integration
- Real-time capabilities

Recommend the smallest stack that meets the requirements.

STOP for approval before introducing major frontend technology.

---

# 23. Evidence and Graph Visualization

Do not implement an evidence graph merely because it looks impressive.

First determine whether the existing Aegis evidence/entity model supports meaningful relationship visualization.

If it does, consider a graph for:

```text
User
  │
Host
  │
Alert
  │
Process
  │
Domain
  │
IP
  │
Threat Intelligence
```

If the relationships are not meaningful enough yet, do not force a graph.

A graph should solve a real investigation problem, not be decorative.

---

# 24. Response and Approval UI

The future UI should expose the existing response workflow clearly.

The user should be able to understand:

```text
Recommended Action
        ↓
Why Recommended
        ↓
Evidence
        ↓
Policy Evaluation
        ↓
Approval Requirement
        ↓
Execution
        ↓
Verification
```

The UI must not allow bypassing existing policy and authorization controls.

The frontend is a client of the authorization system, not the authority itself.

---

# 25. Real-Time Updates

Investigate whether the existing Aegis architecture supports real-time workflow updates.

Potential mechanisms:

- WebSockets
- Server-Sent Events
- Polling

Do not introduce real-time infrastructure unless it provides meaningful value.

For a portfolio project, real-time investigation progress could be valuable for:

```text
Investigation Started
        ↓
Context Retrieved
        ↓
Threat Intelligence Queried
        ↓
Evidence Correlated
        ↓
Assessment Generated
        ↓
Response Proposed
```

Compare options and recommend the simplest approach compatible with the existing architecture.

---

# 26. Security Requirements

Aegis is a security platform, so the integration and UI must be designed securely.

Consider:

- Authentication
- Authorization
- API key management
- Secret handling
- Role-based access control
- Action approval permissions
- CSRF where applicable
- CORS
- Input validation
- Rate limiting
- Audit logging
- Webhook verification if used
- Elasticsearch credentials
- Least privilege
- Separation of read and action permissions

Do not expose:

- Threat-intelligence API keys
- Internal service credentials
- Raw secrets
- Sensitive tool configuration

The UI must never directly access privileged backend credentials.

---

# 27. Trust Boundaries

Document integration trust boundaries:

```text
External Security Events
        │
        ▼
Elastic
        │
        ▼
Aegis Integration Layer
        │
        ▼
Aegis Core
        │
        ▼
Threat Intelligence Providers
        │
        ▼
Response Systems
```

Identify:

- Untrusted inputs
- External data
- Agent/tool boundaries
- Elasticsearch query boundaries
- UI/API boundaries
- Response authorization boundaries

Do not allow external log content to become unrestricted instructions to agents or tools.

---

# 28. Testing Requirements

Create testing around the integration, not only individual UI components.

## Unit Tests

Test:

- Alert normalization
- Elastic adapters
- Mapping between Elastic data and Aegis models
- Result export
- Query builders
- Validation

## Integration Tests

Test:

```text
Elasticsearch
       ↔
Elastic Integration Layer
       ↔
Existing Aegis APIs
```

## End-to-End Tests

Test:

```text
Security Event
       ↓
Elastic Alert
       ↓
Aegis
       ↓
Investigation
       ↓
Enrichment
       ↓
Assessment
       ↓
Response
       ↓
Verification
       ↓
Result in Elasticsearch
       ↓
Visible in Kibana
```

External threat-intelligence APIs should remain mockable.

---

# 29. Local Development and Deployment

Inspect the existing Aegis deployment architecture.

Then recommend the simplest local development environment for:

```text
Aegis
+
Elasticsearch
+
Kibana
```

Prefer reproducible infrastructure.

Consider:

- Docker Compose
- Environment configuration
- Health checks
- Service dependencies
- Startup order
- Persistent volumes
- Local testing

Do not add unnecessary Kubernetes complexity.

The project should be easy for a recruiter or reviewer to run locally.

---

# 30. Portfolio Demonstration Requirements

The final system should be easy to demonstrate.

Create a reproducible demo workflow:

```text
1. Start Aegis + Elastic Stack
2. Ingest or generate realistic security events
3. Show logs in Kibana
4. Trigger a detection
5. Show Aegis receiving the alert
6. Show investigation progress
7. Show threat-intelligence enrichment
8. Show evidence
9. Show assessment
10. Show response recommendation
11. Show approval/policy decision
12. Show execution
13. Show verification
14. Show the completed investigation in Kibana
```

Document:

- Demo setup
- Required API keys
- Environment variables
- Test data
- Expected output
- Screens to capture for the portfolio

---

# 31. Definition of Done — Elastic/Kibana Integration

The integration milestone is complete when:

- [ ] Existing Aegis architecture has been inspected and documented.
- [ ] No unnecessary core components were rebuilt.
- [ ] Elastic integration architecture is documented.
- [ ] Elastic alerts/events can reach Aegis.
- [ ] Aegis can retrieve relevant Elastic context where needed.
- [ ] Existing Aegis investigation workflows run successfully.
- [ ] Existing agents can perform their intended functions.
- [ ] Existing threat-intelligence enrichment is demonstrated.
- [ ] Investigation evidence is available.
- [ ] Assessment is produced.
- [ ] Existing policy/response workflow is demonstrated.
- [ ] Verification is demonstrated where supported.
- [ ] Aegis results are stored or exposed through Elasticsearch.
- [ ] Kibana can visualize the relevant investigation data.
- [ ] The alert can be traced to the corresponding Aegis incident.
- [ ] The complete workflow is reproducible.
- [ ] The integration does not tightly couple Aegis core logic to Kibana.

Only after this milestone is complete should the full custom UI implementation begin.

---

# 32. Definition of Done — Future Aegis SOC UI

The UI phase should be considered complete when the MVP UI allows a user to:

- [ ] View active incidents
- [ ] Open an incident
- [ ] Understand what happened
- [ ] View investigation progress
- [ ] View evidence
- [ ] Distinguish facts from AI inference
- [ ] View threat-intelligence context
- [ ] View recommendations
- [ ] View policy and approval state
- [ ] Approve or reject authorized actions
- [ ] View execution status
- [ ] View verification
- [ ] View the audit trail

The UI should consume Aegis APIs and should not duplicate backend decision logic.

---

# 33. How You Should Work With Me

Do not produce a massive plan and then implement everything without checkpoints.

## Stage A — Repository Inspection

1. Inspect the existing Aegis implementation.
2. Produce the Current State Report.
3. Identify reusable integration points.
4. Identify genuine gaps.
5. Ask only important questions.

Then STOP.

## Stage B — Elastic Integration Architecture

1. Investigate realistic integration options.
2. Compare options.
3. Recommend an architecture.
4. Define the data flow.
5. Identify Elasticsearch storage strategy.
6. Identify security considerations.

Then STOP for approval.

## Stage C — Integration Design

After approval:

1. Design adapters.
2. Define mappings.
3. Define alert/event flow.
4. Define Aegis result export.
5. Define Kibana visualization strategy.
6. Define testing strategy.

Then STOP.

## Stage D — Incremental Implementation

Implement in small milestones.

After each milestone:

1. Explain what changed.
2. Identify files/components changed.
3. Explain what now works.
4. Provide exact testing instructions.
5. Identify remaining gaps.

Do not perform large silent refactors.

## Stage E — End-to-End Validation

Run the complete workflow.

Document:

- What worked
- What failed
- Limitations
- Remaining technical debt

Do not claim the integration is complete if critical steps are mocked or disconnected.

## Stage F — UI Planning

Only after the Elastic/Kibana integration works:

1. Review what information was difficult to access through Kibana.
2. Identify what the custom Aegis UI should improve.
3. Design UI information architecture.
4. Propose MVP pages.
5. Recommend frontend technology.

Then STOP for approval before implementing the UI.

---

# 34. STOP / ASK / ASSUME Protocol

## STOP and ask me when:

- A major architectural decision is required.
- Multiple significantly different integration approaches exist.
- An existing Aegis component must be changed significantly.
- A security trade-off is involved.
- Vendor lock-in may be introduced.
- Existing data models need breaking changes.
- A destructive response capability is being added.
- A new major technology/framework is proposed.

## ASK only when:

The answer materially changes the architecture or implementation.

Do not interrupt for minor details that can be reasonably inferred.

## ASSUME when:

- The assumption is minor.
- It is reversible.
- It does not create security or architectural risk.

Record assumptions explicitly.

---

# 35. Assumption and Decision Logs

Maintain:

## Assumption Log

```text
ID
Assumption
Reason
Impact
Status
```

## Architecture Decision Record

```text
Decision ID
Context
Options Considered
Decision
Reason
Trade-offs
Status
```

Do not silently forget earlier decisions.

---


---

# 35A. Priority Hierarchy

When requirements, implementation choices, or design goals conflict, prioritize them in this order:

```text
1. Security and trust boundaries
2. Existing Aegis architecture and working functionality
3. Correct end-to-end incident lifecycle
4. Data integrity and auditability
5. Clean architecture and loose coupling
6. Working Elastic/Kibana integration
7. API stability for the future Aegis UI
8. UI usability and operational clarity
9. Visual polish
10. Optional features
```

Do not sacrifice a higher-priority requirement to achieve a lower-priority requirement.

If a trade-off affects two high-priority requirements, explicitly explain the trade-off and STOP for approval when the decision is materially architectural, security-sensitive, or difficult to reverse.

---

# 35B. Integration Integrity Rule

Do not represent a mocked, hardcoded, manually injected, or disconnected workflow as a working integration.

For every major feature or demonstration step, clearly identify whether it is:

- Fully implemented and connected
- Partially implemented
- Mocked
- Simulated
- Planned

The final demo must clearly distinguish real system behavior from simulated data.

Mocked external threat-intelligence providers are acceptable for tests when necessary, but the integration boundaries, data flow, and Aegis workflow being demonstrated must remain representative of the real architecture.

Do not create UI states, dashboards, or screenshots that imply a backend capability exists when it is not actually connected.

---

# 35C. Demonstrability Test

Before introducing a new component, service, framework, architectural layer, or major dependency, evaluate:

1. What concrete problem does this solve?
2. Does the existing Aegis architecture already solve it?
3. Is it necessary for the end-to-end workflow?
4. Does it improve security, correctness, reliability, or operational usability?
5. Can its value be demonstrated or justified?
6. What operational complexity does it introduce?
7. Can the same result be achieved more simply?

Do not add architecture merely because it is technically interesting or commonly used.

Prefer the simplest design that preserves:

- Security
- Correctness
- Traceability
- Extensibility
- Demonstrability

Avoid microservices, message queues, orchestration layers, databases, frameworks, or visualization components unless they solve a real requirement.

---

# 35D. Evidence Provenance Requirement

Where the existing Aegis data model supports it, evidence should preserve or expose appropriate provenance metadata.

Relevant provenance may include:

- Source
- Collection time
- Collection method
- Related incident
- Related entity
- Related investigation or correlation step
- Original event, document, or provider reference
- Whether the information is observed, external, derived, or inferred

The system should clearly distinguish:

```text
Observed telemetry
        ≠
External evidence
        ≠
Derived correlation
        ≠
AI/system inference
```

Do not present derived conclusions as raw evidence.

If the current Aegis implementation does not preserve sufficient provenance for the intended workflow, identify the gap and propose the smallest backward-compatible change.

---

# 35E. Architecture Freeze Checkpoint

Before beginning the full custom Aegis SOC UI implementation, perform an architecture freeze review.

Confirm:

- [ ] Elastic/Kibana integration works end-to-end.
- [ ] The relevant Aegis APIs expose the operational data required by the UI.
- [ ] Incident lifecycle state is stable.
- [ ] Investigation, evidence, assessment, response, and verification flows are functioning.
- [ ] Remaining backend gaps required specifically for UI support have been identified.
- [ ] Major architecture decisions have been documented.
- [ ] No unnecessary backend redesign is pending.

At this checkpoint, provide a concise Architecture Freeze Report containing:

1. Stable architecture summary
2. Confirmed API contracts
3. Remaining known limitations
4. UI-specific backend gaps
5. Changes that are explicitly deferred
6. Recommended UI MVP scope

Then STOP for approval before beginning the full custom UI implementation.

Once UI implementation begins, avoid changing backend architecture unless a genuine:

- Security issue
- Correctness issue
- Integration failure
- API contract problem

requires it.

Do not repeatedly redesign the backend while building the frontend.


# 36. Final Principles

The objective is NOT:

> Put Aegis inside Kibana.

The objective is:

> **Integrate an independent AI-native security incident operations platform with an existing SIEM so that real security events can be investigated, enriched, assessed, responded to, verified, and demonstrated through a familiar SOC workflow.**

Priorities:

```text
Reuse Existing Aegis
        >
Security and Trust Boundaries
        >
Correct End-to-End Incident Lifecycle
        >
Data Integrity, Evidence Provenance, and Auditability
        >
Clean Architecture and Loose Coupling
        >
Working Elastic/Kibana Integration
        >
Stable APIs for the Future UI
        >
Aegis-Specific Operational UI
        >
Visual Polish
        >
Optional Features
```

Do not redesign working Aegis components without justification.

Do not build a fake demo.

Do not build UI screens disconnected from real backend workflows.

The end goal is a polished portfolio project where:

```text
Elastic / Kibana
        +
Aegis Core
        +
Real Agents
        +
Real Threat Intelligence
        +
Evidence
        +
Policy-Controlled Response
        +
Verification
```

work together as one coherent security operations system.

---

# Start Here

Your first action is:

> **Inspect the existing Aegis repository and produce the Current State Report described in Section 5. Do not make major changes until the existing architecture and integration points are understood.**
