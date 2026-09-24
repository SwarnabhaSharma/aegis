# AEGIS UI Visual Reference, Design Direction & Implementation Plan — Final v2

## Purpose

I am providing two UI reference images for the AEGIS interface.

You must study both reference images before making UI implementation decisions.

These images represent the intended **design direction, product vision, screen coverage, UX concepts, and level of polish** for AEGIS.

However, they are **not pixel-perfect specifications** and must not be blindly copied.

The objective is to intelligently translate the visual direction into a real, coherent interface based on the existing AEGIS implementation.

---

# 1. Your First Task — Inspect Before Building

Before writing or modifying major UI code:

1. Inspect the existing AEGIS frontend.
2. Inspect the existing AEGIS backend.
3. Inspect available APIs, events, services, and domain models.
4. Review the existing AEGIS master/integration requirements already provided.
5. Study both UI reference images.
6. Identify which concepts shown in the references are supported by the actual AEGIS implementation.
7. Identify concepts that require additional integration or backend APIs.
8. Identify concepts that are currently unsupported.
9. Identify the current frontend architecture and technology stack.
10. Propose a UI implementation plan based on the real system.

Do not immediately attempt to build every screen shown in the references.

First produce the reports described below.

---

# 2. Required Initial Deliverables

Before major implementation, provide:

## A. UI Capability Mapping Report

For each significant UI concept, determine:

- Whether the required functionality exists.
- Which backend service or API provides the data.
- Whether the capability is fully supported, partially supported, missing, or deferred.
- What minimal changes are required.
- Whether the feature belongs in the MVP.

Use a mapping similar to:

| UI Concept | Existing AEGIS Support | Data/API Source | Status | MVP | Recommendation |
|---|---|---|---|---|---|
| Incident Queue | Inspect actual implementation | Identify actual API | Determine | Yes/No | Implement / Extend / Defer |
| Incident Detail | Inspect actual implementation | Identify actual API | Determine | Yes/No | Implement / Extend / Defer |
| Investigation Workspace | Inspect actual implementation | Identify actual API | Determine | Yes/No | Implement / Extend / Defer |
| Agent Activity | Inspect actual implementation | Identify actual API/events | Determine | Yes/No | Implement / Extend / Defer |
| Response Center | Inspect actual implementation | Identify actual API | Determine | Yes/No | Implement / Extend / Defer |
| Approval Workflow | Inspect actual implementation | Identify actual API | Determine | Yes/No | Implement / Extend / Defer |
| Attack Chain | Inspect actual implementation | Identify relationship data | Determine | Yes/No | Implement / Extend / Defer |
| Privacy View | Inspect actual implementation | Identify audit/access data | Determine | Yes/No | Implement / Extend / Defer |
| Audit Replay | Inspect actual implementation | Identify event history | Determine | Yes/No | Implement / Extend / Defer |

Do not assume the example rows above are already supported.

The actual AEGIS implementation is the source of truth.

---

## B. Proposed MVP Scope

Define the smallest version of the AEGIS UI that provides a polished, coherent, end-to-end operational workflow.

The MVP should prioritize:

```text
Overview
    ↓
Incident Queue
    ↓
Incident Detail
    ↓
Investigation & Evidence
    ↓
Agent Activity
    ↓
Assessment / Decision
    ↓
Response & Approval
    ↓
Execution & Verification
    ↓
Audit Trail
```

Do not automatically include every screen from the reference images.

Prefer:

> A smaller number of deeply integrated, polished screens.

over:

> A large number of partially functional pages.

---

## C. Information Architecture Proposal

Based on the actual AEGIS capabilities, propose the recommended navigation structure.

The reference direction may evolve toward:

```text
AEGIS
│
├── Overview
│
├── Incidents
│     ├── Incident Queue
│     └── Incident Detail
│
├── Investigations
│     ├── Evidence
│     ├── Timeline
│     └── Analysis
│
├── Agent Activity
│
├── Threat Intelligence
│
├── Response
│     ├── Recommended Actions
│     ├── Approvals
│     ├── Execution
│     └── Verification
│
├── Assets
│
├── Audit & Replay
│
├── Privacy & Data Access
│
└── Settings & Integrations
```

This is a **target direction**, not a requirement to implement every section.

Adapt it to the actual AEGIS system.

---

## D. API and Backend Gap Report

Identify:

### Required Gaps
Capabilities necessary for the MVP that currently lack sufficient data or APIs.

### Recommended Gaps
Capabilities that would significantly improve the product but are not required for the MVP.

### Optional Future Improvements
Advanced capabilities that should be deferred until the core workflow is complete.

Do not make major backend architectural changes without presenting them for review.

---

# 3. How to Use the Reference Images

## Reference Image 1 — Multi-Screen AEGIS UI Concept

Use this image primarily to understand:

- Overall AEGIS information architecture
- Potential screen structure
- Incident lifecycle
- Investigation workflows
- Agent operations
- Response and approval workflows
- Attack chain visualization
- Privacy and data access
- Audit replay
- Settings and integrations

Potential screens shown include:

- Security Operations Overview
- Incident Queue
- Incident Detail
- Investigation Workspace
- Agent Activity
- Response & Approval
- Attack Chain Visualization
- Privacy & Data Access
- Audit Replay
- Settings & Integrations

Do not assume every screen must be implemented immediately.

Determine whether each concept is supported by actual AEGIS functionality and whether it belongs in the MVP.

---

## Reference Image 2 — Security Operations Dashboard

Use this image as the **primary visual design reference**.

Study it for:

- Dark SOC/security operations aesthetic
- Layout
- Navigation
- Sidebar design
- Dashboard composition
- Information density
- Card design
- Table design
- Typography hierarchy
- Spacing
- Incident severity visualization
- Status indicators
- Panel composition
- Overall polish level

The final AEGIS UI should aim for a similar level of:

- Professional polish
- Information density
- Operational clarity
- Visual consistency

Do not copy the interface pixel-for-pixel.

Where the two reference images differ, prioritize a consistent AEGIS design system rather than combining layouts blindly.

---

# 4. AEGIS UI Identity

The AEGIS UI must feel like an:

> **AI-Native Security Incident Operations Platform**

It must NOT feel like:

- A generic admin dashboard
- A Kibana clone
- A simple SIEM dashboard
- A chatbot with security widgets
- A collection of disconnected AI-generated summaries
- A marketing website

The primary interface should be an operational security console centered around:

```text
Incidents
    ↓
Investigation
    ↓
Evidence
    ↓
Agent Activity
    ↓
Assessment
    ↓
Policy & Authorization
    ↓
Response
    ↓
Verification
    ↓
Audit & Replay
```

The UI should help a security analyst understand:

1. What happened?
2. What evidence supports it?
3. What did AEGIS investigate?
4. What did the agents do?
5. What is observed versus inferred?
6. What action was recommended?
7. What was authorized?
8. What was actually executed?
9. Was the outcome independently verified?

---

# 5. The Existing AEGIS System Is the Source of Truth

The reference images are not the source of truth.

The existing AEGIS:

- Backend
- Domain model
- APIs
- Event model
- Security architecture
- Agent architecture
- Policy and authorization logic

remain authoritative.

Do NOT create:

- Fake incidents
- Fake agents
- Fake response actions
- Fake integrations
- Fake metrics
- Fake threat intelligence
- Fake policy decisions

merely because they appear in the reference images.

Do not sacrifice backend correctness or trust boundaries for visual polish.

---

# 6. Implementation Decision Protocol

For every proposed UI capability, follow this decision process.

## Step 1 — Verify Existing Support

Inspect the actual AEGIS:

- Backend
- APIs
- Events
- Domain models
- Services
- Existing frontend functionality

Do not infer support from UI references or documentation alone.

---

## Step 2 — Classify the Capability

Classify each capability as:

### Ready

Real backend/API support exists.

### Partial

Some required functionality exists, but additional integration or a small API extension is required.

### Missing

The required backend capability does not exist.

### Deferred

The capability is not required for the current MVP.

---

## Step 3 — Decide the Implementation Path

### Ready

Implement the feature using real AEGIS data.

### Partial

Identify the smallest integration or API change required.

Prefer:

- Extending existing APIs
- Reusing existing domain models
- Adding minimal adapters

Avoid:

- Creating parallel systems
- Duplicating existing data
- Introducing unnecessary services

### Missing

Do not invent the capability.

Document:

- Why the capability is valuable
- What data or events would be required
- The smallest proposed implementation
- Whether it is required for the MVP

Do not make major architectural backend changes without presenting them for review.

### Deferred

Do not create placeholder pages merely to reproduce the reference images.

The UI should remain coherent even when future capabilities are not yet implemented.

---

# 7. Development Data Policy

Do not represent mocked or simulated data as real AEGIS operational data.

However, development fixtures or mock data may be used when necessary for:

- Component development
- Local UI development
- Component testing
- Story/demo states
- Empty state development
- Error state development
- Demonstrating clearly unavailable states

Mock or fixture data must:

- Be isolated from production API data
- Never be silently presented as live system data
- Be easy to replace with real API integration
- Not influence backend decisions or workflows
- Be clearly distinguishable during development and demonstrations when appropriate

The final product should use real AEGIS data wherever the capability exists.

Do not build the production architecture around mock data.

---

# 8. Required Design Principles

The UI should prioritize:

- Operational clarity
- Information hierarchy
- Evidence traceability
- Explainability
- Agent transparency
- Privacy visibility
- Response safety
- Auditability
- Consistency
- Professional polish

Avoid:

- Excessive animations
- Oversized cards
- Excessive empty whitespace
- Generic AI illustrations
- Dashboard clutter
- Unnecessary charts
- Excessive gradients
- Decorative elements that reduce operational clarity
- Visualizations that exist only because they look impressive

This is a security operations platform, not a marketing website.

---

# 9. Trust Boundary Visualization

The UI must clearly distinguish between:

```text
OBSERVED FACT
        ↓
Direct telemetry or deterministic event

EVIDENCE
        ↓
Supporting information with provenance

THREAT INTELLIGENCE
        ↓
External enrichment

AEGIS ASSESSMENT
        ↓
System or AI inference

POLICY DECISION
        ↓
Authorization or deterministic policy outcome

HUMAN DECISION
        ↓
Approval, rejection, or override

EXECUTION RESULT
        ↓
Action attempted or completed

VERIFICATION RESULT
        ↓
Independently confirmed outcome
```

Do not visually present all information as equally trustworthy.

The analyst must be able to distinguish:

> What was observed, what was inferred, what was authorized, what was executed, and what was verified.

Where possible, provide:

- Source
- Timestamp
- Provenance
- Confidence or reliability where meaningful
- Relationship to the incident

Do not expose hidden chain-of-thought or private model reasoning.

---

# 10. Frontend Integration Architecture

Do not tightly couple UI components directly to raw backend response structures.

Prefer the following architecture:

```text
AEGIS Backend
      ↓
API Client
      ↓
API Adapter / Mapper
      ↓
Frontend Domain Model
      ↓
Reusable UI Components
```

Benefits:

- Backend changes have limited UI impact
- UI components remain reusable
- API inconsistencies can be normalized
- Domain concepts remain consistent across screens
- Presentation logic remains separate from transport concerns

Do not duplicate authoritative business logic from the backend in the frontend.

Backend:

- Policy enforcement
- Authorization
- Execution decisions
- Security controls

must remain authoritative.

The frontend should display and invoke backend decisions, not replace them.

---

# 11. Core UI Structure

The final UI should evolve toward the following structure, depending on actual AEGIS capabilities:

```text
AEGIS
│
├── Overview
│
├── Incidents
│     ├── Incident Queue
│     └── Incident Detail
│
├── Investigations
│     ├── Evidence
│     ├── Timeline
│     └── Analysis
│
├── Agent Activity
│
├── Threat Intelligence
│
├── Response
│     ├── Recommended Actions
│     ├── Approvals
│     ├── Execution
│     └── Verification
│
├── Assets
│
├── Audit & Replay
│
├── Privacy & Data Access
│
└── Settings & Integrations
```

This is a target information architecture, not a requirement to build every section immediately.

Adapt it to the actual AEGIS implementation.

---

# 12. Recommended MVP Scope

The objective is not to reproduce every screen shown in the reference images.

The first polished AEGIS UI should prioritize a complete operational workflow.

Recommended MVP:

## 1. Application Shell and Navigation

- Consistent sidebar
- Page layout
- Global search where supported
- Navigation
- Shared design system
- Core status and severity patterns

## 2. Security Operations Overview

A high-level view of operational security posture using real system data.

## 3. Incident Queue

A prioritized view answering:

> What requires attention right now?

## 4. Incident Detail

A central workspace showing:

- Incident summary
- Severity
- Status
- Timeline
- Evidence
- Threat intelligence
- Investigation progress
- Agent activity
- Assessment
- Response state

## 5. Investigation and Evidence

A clear way to understand:

- What was observed
- What evidence was collected
- What enrichment was performed
- What relationships exist

## 6. Agent Activity

Operational visibility into:

- Agent role
- Current or completed task
- Status
- Tool usage
- Result summary
- Failures and retries
- Escalations

## 7. Response and Approval

A clear path from:

```text
Recommendation
      ↓
Supporting Evidence
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
Independent Verification
```

## 8. Audit Trail

A reconstructable history of the incident lifecycle where supported by AEGIS.

Everything else should be evaluated after the core workflow is polished.

---

# 13. Core Screen Requirements

## Security Operations Overview

The dashboard should provide a high-level operational view.

Potential components include:

- Active incidents
- Awaiting approvals
- Active investigations
- Response success
- Threats enriched
- Incident trends
- Incident distribution
- Affected assets
- Recent incidents
- Live agent activity
- Threat intelligence summary
- System health

Only show metrics supported by actual system data.

Avoid metrics that look impressive but do not provide operational value.

---

## Incident Queue

Focus on helping analysts answer:

> What requires attention right now?

Potential fields:

- Severity
- Incident ID
- Title
- Affected assets
- Investigation status
- Response status
- Updated time

Support where useful:

- Search
- Filtering
- Sorting
- Severity prioritization

Use the actual AEGIS incident model and lifecycle.

---

## Incident Detail

This should be one of the most important AEGIS screens.

It should clearly communicate:

```text
Incident Summary
       │
       ├── Timeline
       ├── Observed Facts
       ├── Evidence
       ├── Threat Intelligence
       ├── Agent Activity
       ├── Assessment
       ├── Policy / Authorization
       ├── Response
       └── Verification
```

Avoid hiding important operational information behind unnecessary navigation.

The screen should allow an analyst to understand the incident without reading disconnected AI-generated summaries.

---

## Agent Activity

Show useful operational information such as:

- Agent role
- Current task
- Status
- Investigation stage
- Tool usage
- Authorization state
- Result summary
- Failure/retry state
- Escalations

Do NOT expose hidden chain-of-thought or private internal model reasoning.

The goal is:

> Operational transparency without exposing private reasoning.

---

## Response & Approval

Clearly represent:

```text
Recommendation
      ↓
Supporting Evidence
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
Independent Verification
```

The UI must never bypass backend authorization or policy enforcement.

The UI should make clear:

- Who or what recommended the action
- Why it was recommended
- What evidence supports it
- Whether approval is required
- Who approved or rejected it
- What was executed
- What verification confirmed

---

## Attack Chain / Entity Relationships

Only implement this if meaningful entity relationships and evidence connections exist.

Possible relationships:

```text
User
 ↓
Host
 ↓
Process
 ↓
Network Connection
 ↓
IP / Domain
 ↓
Alert
 ↓
Threat Intelligence
```

Do not create a graph merely because graphs look visually impressive.

If a timeline, relationship table, or evidence view is more useful, prefer that.

---

## Privacy & Data Access

Where supported by AEGIS, show:

- Data requested
- Data accessed
- Data withheld
- Data classification
- Access purpose
- Privacy decisions
- Redaction decisions
- Relevant authorization decisions

The goal is to answer:

> What data did AEGIS access, and why?

Never expose sensitive information unnecessarily merely to demonstrate transparency.

---

## Audit & Incident Replay

The system should eventually allow reconstruction of:

> Exactly what happened during an incident and why.

Potential replay events:

- Alert triggered
- Investigation started
- Evidence collected
- Data accessed
- Threat intelligence retrieved
- Agents invoked
- Tool requests
- Policy decisions
- Authorization decisions
- Human approvals
- Response execution
- Verification
- Errors and retries

This should function as a genuine operational audit trail, not merely an animated timeline.

---

# 14. Visual Consistency and Design System

Build a reusable design system before implementing many screens.

Create reusable components for:

- Navigation
- Page headers
- Metric cards
- Status badges
- Severity indicators
- Tables
- Filters
- Search
- Tabs
- Timeline events
- Evidence cards
- Agent status
- Approval actions
- Empty states
- Loading states
- Error states
- Confirmation dialogs where appropriate

Do not independently design each page.

The final platform should feel like:

> One coherent product.

Maintain consistency in:

- Spacing
- Typography
- Color semantics
- Severity representation
- Status representation
- Interaction patterns
- Tables and filters
- Empty and error states

---

# 15. Required Data States

Every data-driven screen should handle:

## Loading

Show an appropriate loading state.

Avoid blank screens or layout shifts.

## Empty

Clearly explain when no data is available.

Where appropriate, explain why.

## Error

Show meaningful error feedback.

Avoid vague messages such as:

> Something went wrong.

Provide a retry mechanism where appropriate.

## Partial Data

Gracefully handle cases where some incident or enrichment information is unavailable.

Do not cause the entire screen to fail because one optional source is unavailable.

## Stale Data

Where the system exposes timestamps or freshness information, make stale data understandable.

## Unauthorized Access

Do not expose restricted information.

Handle permission failures clearly and safely.

---

# 16. Screen Completion Criteria

A screen is not complete merely because it renders.

For every major data-driven screen, verify:

- Real API integration where supported
- Correct loading state
- Correct empty state
- Correct error state
- Graceful handling of partial data
- Clear handling of unavailable functionality
- Responsive layout
- Consistent navigation
- Consistent design-system components
- No misleading mock production data
- Correct connection to backend actions and workflows
- No frontend bypass of backend security controls

Before marking a major screen complete, verify that the screen helps the user perform a real AEGIS workflow.

---

# 17. No Fake Integration Rule

Do not represent mocked or disconnected functionality as real.

For each major UI capability, identify whether it is:

- Fully implemented
- Partially implemented
- Mocked for development/testing
- Simulated
- Planned

The final UI and demo must clearly distinguish real functionality from mock data.

Do not create buttons that appear operational but do nothing without clearly indicating that the functionality is unavailable.

---

# 18. Avoid Over-Engineering

This is a polished portfolio project, not an enterprise product with unlimited development resources.

Do not introduce unnecessary complexity.

Avoid:

- Building microservices solely for the UI
- Creating unnecessary backend services
- Adding complex state management without justification
- Building a graph engine unless relationships require one
- Creating screens without real user value
- Implementing advanced features solely because they look impressive
- Rewriting working AEGIS backend functionality unnecessarily

Prefer:

> Simple, maintainable architecture with strong real functionality.

A smaller number of deeply integrated, polished features is more valuable than a large number of superficial features.

---

# 19. Recommended Implementation Order

Do not build every screen simultaneously.

Recommended sequence:

```text
PHASE 0
Inspect Existing AEGIS
Capability Mapping
MVP Definition
Architecture Decisions
        ↓
PHASE 1
UI Shell
Navigation
Design System
API Client / Adapters
Core Components
        ↓
PHASE 2
Security Operations Overview
        ↓
PHASE 3
Incident Queue
        ↓
PHASE 4
Incident Detail
Investigation Timeline
Evidence Views
        ↓
PHASE 5
Agent Activity
        ↓
PHASE 6
Response & Approval
        ↓
PHASE 7
Execution & Verification Visibility
        ↓
PHASE 8
Audit Trail / Replay
        ↓
PHASE 9
Advanced Features
Attack Chain / Entity Visualization
Privacy & Data Access
Settings & Integrations
```

Adjust this sequence if the actual AEGIS implementation reveals a better dependency order.

Explain any major changes.

---

# 20. Implementation Workflow

After producing the initial reports:

1. Propose the MVP scope.
2. Identify the first implementation phase.
3. Identify required frontend changes.
4. Identify required backend/API changes.
5. Separate:
   - Required changes
   - Recommended changes
   - Optional future improvements
6. Present major architectural decisions for review.
7. After approval, implement one phase at a time.
8. At the end of each phase, report:
   - What was implemented
   - What uses real backend data
   - What remains mocked or simulated
   - Any API gaps discovered
   - Any new architectural decisions required
   - Recommended next phase

Do not repeatedly stop for approval on minor implementation details.

Use reasonable engineering judgment for small decisions.

---

# 21. When to Stop and Ask for Review

Pause and ask for review only when a decision involves:

- Major architectural changes
- Significant backend changes
- Security boundary changes
- Policy or authorization changes
- Large dependency additions
- Major data-model changes
- Multiple substantially different implementation options
- Changes that alter the original AEGIS architecture
- Scope changes that materially expand the project

Do NOT stop for approval over:

- Minor styling decisions
- Small component structure decisions
- Naming conventions
- Routine implementation details
- Minor layout adjustments

Document reasonable engineering decisions and continue.

---

# 22. Final UI Quality Standard

The target quality level is:

> **A polished, modern, professional security product that could plausibly be used by a SOC analyst.**

The goal is not simply to make the UI attractive.

The UI must improve the analyst's ability to:

- Understand incidents
- Investigate evidence
- Monitor agent activity
- Review decisions
- Approve sensitive actions
- Track response execution
- Verify outcomes
- Audit the entire incident lifecycle

Visual polish must support operational usability.

---

# 23. Immediate Next Step

Do not begin implementing the full UI immediately.

First:

1. Inspect the existing AEGIS implementation.
2. Review the existing master/integration requirements.
3. Study both UI reference images.
4. Produce the **UI Capability Mapping Report**.
5. Produce the **MVP Scope Proposal**.
6. Propose the **Information Architecture**.
7. Identify **API and Backend Gaps**.
8. Propose the **Implementation Plan and Phase Order**.
9. Identify any **major architectural decisions requiring review**.

Then STOP and present these findings for review before proceeding with major implementation.

---

# 24. Final Instruction

The two reference images communicate the intended product vision and visual direction.

Your task is to intelligently translate that vision into a real, coherent AEGIS interface based on the existing implementation.

Do not clone the images.

Do not invent unsupported functionality.

Do not sacrifice backend correctness or trust boundaries for visual polish.

Do not over-engineer the project.

Do not build superficial pages merely to reproduce the reference images.

The existing AEGIS architecture and actual capabilities remain the source of truth.

The goal is to build:

> **A cohesive, polished, AI-native security incident operations console that makes AEGIS's real capabilities understandable, usable, trustworthy, and demonstrable.**

Prioritize:

```text
Real Functionality
        ↓
Operational Usability
        ↓
Trust & Evidence Visibility
        ↓
Maintainable Architecture
        ↓
Visual Polish
```

The final result should feel like one coherent security product rather than a collection of dashboards.

---

# 25. Preserve Existing Functionality

AEGIS already contains working functionality. UI work must not unnecessarily disrupt or replace it.

Before modifying existing backend or frontend code:

- Understand the current behavior and dependencies.
- Identify whether existing functionality can be reused or extended.
- Avoid rewriting working functionality without a clear technical reason.
- Prefer additive and incremental changes.
- Preserve existing APIs unless a change is necessary and justified.
- Do not break existing agent workflows, integrations, policy enforcement, authorization, incident processing, enrichment, or response execution.

When modifying an existing interface or service, document:

- What existed before.
- What is being changed.
- Why the change is necessary.
- Which existing behavior must remain unchanged.

After each major implementation phase:

1. Verify that existing functionality still works.
2. Verify that UI changes have not altered backend security behavior.
3. Check for regressions in existing workflows.
4. Identify and fix regressions before proceeding to the next phase.

Do not trade working AEGIS functionality for visual redesign.

---

# 26. Testing and Verification

Do not consider functionality complete merely because the code compiles or the UI renders.

For every major implementation phase:

1. Run existing tests where available.
2. Add tests for new critical functionality where practical.
3. Verify real API integration.
4. Test loading states.
5. Test empty states.
6. Test error states.
7. Test partial-data scenarios.
8. Verify authorization-sensitive actions.
9. Verify that frontend actions cannot bypass backend policy enforcement.
10. Perform an end-to-end workflow test where practical.

Prioritize testing for:

- Incident retrieval
- Incident investigation
- Evidence display
- Threat intelligence enrichment
- Agent activity visibility
- Response recommendations
- Approval workflows
- Response execution
- Verification
- Audit history

For security-sensitive actions, verify both:

```text
UI behavior
        AND
Backend enforcement
```

The UI must never be treated as the security boundary.

Do not claim a workflow is complete without verifying the relevant end-to-end behavior.

When a full automated test is impractical, document the manual verification steps clearly.

---

# 27. Incremental Integration Rule

Do not automatically rewrite the existing frontend because a new visual direction has been provided.

First determine:

- What can be reused.
- What should be extended.
- What should be refactored.
- What should be replaced.
- What should remain untouched.

Prefer incremental improvement and targeted refactoring over a complete rewrite unless the existing architecture makes incremental work impractical.

If recommending a significant rewrite, provide:

1. Why incremental improvement is insufficient.
2. What architectural limitations require replacement.
3. What risks the rewrite introduces.
4. Which functionality must be preserved.
5. How the migration will occur.
6. How regressions will be prevented.
7. Whether the rewrite is required for the MVP.

Do not perform a major rewrite without review when a safer incremental path is available.

---

# 28. Frontend Operational Observability

The AEGIS UI should make failures diagnosable without unnecessarily exposing sensitive security data.

Where appropriate:

- Surface meaningful client-side errors.
- Clearly distinguish frontend failures from backend or integration failures when possible.
- Preserve correlation IDs or request IDs when they are already available.
- Provide useful context for failed API operations.
- Avoid swallowing errors silently.
- Avoid logging sensitive incident data unnecessarily.
- Avoid exposing secrets, tokens, raw credentials, or restricted telemetry in browser logs.

Do not add external telemetry or analytics services unless there is a clear justification.

Prefer lightweight, privacy-conscious observability that helps diagnose:

- Failed API requests
- Integration failures
- Unexpected response shapes
- Authorization failures
- Action execution failures

Operational diagnostics should support the system without creating a new data exposure risk.

---

# 29. Accessibility Requirements

The dark security operations aesthetic must not sacrifice accessibility.

The UI should support:

- Keyboard navigation
- Visible focus states
- Semantic HTML where appropriate
- Accessible labels for controls
- Accessible form validation
- Readable text contrast
- Screen-reader-friendly interactive elements where practical
- Clear status communication
- Non-color-only severity indicators

Do not communicate important states using color alone.

For example, severity should not rely solely on:

```text
Red
Orange
Yellow
Green
```

Use additional indicators such as:

- Text labels
- Icons
- Badges
- Shapes
- Positioning where appropriate

Accessibility should be built into reusable design-system components rather than added as an afterthought.

---

# 30. Portfolio and Demonstration Readiness

AEGIS is intended to become a polished portfolio and resume project.

Once the MVP is complete, identify one or more complete demonstration workflows that showcase the system end-to-end.

A strong demonstration should, where supported by the actual AEGIS implementation, show:

1. Incident ingestion or creation.
2. Incident detection or entry into the workflow.
3. Investigation initiation.
4. Evidence collection.
5. Threat intelligence enrichment where applicable.
6. Agent activity.
7. Assessment.
8. Recommended response.
9. Policy and authorization decision.
10. Human approval where required.
11. Response execution.
12. Independent verification.
13. Audit trail or incident history.

The goal is to demonstrate real AEGIS functionality, not a scripted fake dashboard.

For each recommended demo scenario, document:

- Demo objective
- Required setup
- Required services
- Required API keys or environment configuration
- Input or triggering event
- Expected workflow
- Expected outputs
- Screens involved
- Known limitations
- Which parts are real versus simulated

Do not require every demo to showcase every feature.

Prefer a small number of clear, reliable, end-to-end demonstrations over an overly complex demo that can fail easily.

The final project should be easy to explain in:

- A resume
- A portfolio
- A GitHub README
- A technical interview
- A live demonstration

When the MVP is complete, recommend the strongest end-to-end scenario for showcasing AEGIS.

---

# 31. Final Completion Standard

The UI implementation should not be considered complete simply because all planned pages exist.

The MVP is complete when:

- The core incident workflow works end-to-end.
- The most important screens use real AEGIS functionality.
- Trust boundaries are clearly represented.
- Evidence and provenance are understandable.
- Agent activity is operationally visible without exposing private reasoning.
- Security-sensitive actions remain backend-authorized.
- Loading, empty, error, and partial-data states are handled.
- Existing AEGIS functionality has been preserved.
- Critical workflows have been tested or manually verified.
- The interface is coherent and visually consistent.
- The system can be demonstrated through at least one meaningful end-to-end workflow.

Prioritize completion quality over page count.

The final result should demonstrate:

```text
Real Security Workflow
        +
Real AEGIS Integration
        +
Clear Trust Boundaries
        +
Operational Usability
        +
Professional Visual Polish
```

Do not add features solely to increase the apparent size or complexity of the project.

A polished, reliable, understandable AEGIS MVP is more valuable than a larger but partially functional platform.
