"""Slice orchestration core — single path shared by CLI, API, and tests.

investigate(): TRIAGING -> RESPONSE_PLANNED -> policy decision
              (agentic when a registry is passed; evidence persistence +
              intel seeding always on).
run_full_slice(): investigate + simulated execute/verify tail (CLI/tests).
"""

import os
from dataclasses import replace

from aegis.agents.pipeline import AgentPipeline
from aegis.executor.executor import SimulatedExecutor
from aegis.incidents.evidence import evidence_from_tool_result
from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.schema import IncidentState
from aegis.integrations.llm import LLMClient
from aegis.orchestrator.engine import Orchestrator
from aegis.policies.engine import Decision, evaluate
from aegis.verifier.verifier import SimulatedVerifier


class FakeLLM(LLMClient):
    """Offline deterministic stand-in for llama.cpp (CLI --llm fake / tests)."""

    def __init__(self) -> None:
        pass

    def complete_json(self, system, user, temperature=0.0):
        from aegis.integrations.llm import LLMResult

        data = {
            "classification": "malicious", "severity": "high",
            "investigate": True, "reason": "synthetic",
            "evidence_ids": ["ev-1"], "summary": "synthetic slice",
            "hypotheses": [], "open_questions": [],
            "attack_chain": [], "affected_assets": ["win-vm"],
            "assessment": "malicious", "confidence": 0.95,
            "attack_mapping": "T1059.001",
            "recommended_actions": ["isolate_host"],
            "rationale": "test", "risks": [],
        }
        return LLMResult(ok=True, data=data, raw="{}")


def make_store():
    """Store per AEGIS_STORE env (mirrors api.py). Returns (store, es|None)."""
    if os.getenv("AEGIS_STORE") == "es":
        from elasticsearch import Elasticsearch

        from aegis.config import get_settings
        from aegis.incidents.es_store import ElasticsearchStore

        s = get_settings()
        es = Elasticsearch(
            s.es_host, basic_auth=(s.es_user, s.es_password),
            verify_certs=s.es_verify_certs, request_timeout=60,
        )
        return ElasticsearchStore(es), es
    from aegis.incidents.store import InMemoryStore

    return InMemoryStore(), None


def live_telemetry():
    from elasticsearch import Elasticsearch

    from aegis.config import get_settings
    from aegis.tools.es_telemetry import ElasticsearchTelemetry

    s = get_settings()
    es = Elasticsearch(
        s.es_host, basic_auth=(s.es_user, s.es_password),
        verify_certs=s.es_verify_certs, request_timeout=60,
    )

    return es, ElasticsearchTelemetry(es)


def build_registry(controls=None):
    """Production read-tool registry backed by live winlogbeat telemetry."""
    from aegis.tools.registry import build_read_tools

    es, tel = live_telemetry()
    return es, build_read_tools(tel, controls=controls)


def _synthetic_events(host: str):
    """Canned telemetry matching the slice story (Word -> encoded PS -> C2)."""

    from aegis.tools.telemetry import TelemetryEvent

    return [
        TelemetryEvent(
            event_id="1", channel="sysmon", action="ProcessCreate", host=host,
            process_name="powershell.exe", process_pid="1000",
            process_parent="WINWORD.EXE", command_line="powershell -enc SQBFAFA7AFIA",
        ),
        TelemetryEvent(
            event_id="3", channel="sysmon", action="NetworkConnect", host=host,
            process_name="powershell.exe", process_pid="1000",
            destination_ip="185.220.101.4", destination_port="443",
        ),
        TelemetryEvent(
            event_id="11", channel="sysmon", action="FileCreate", host=host,
            process_name="powershell.exe", process_pid="1000",
            file_path="C:\\ProgramData\\payload.dll",
        ),
    ]


def _fmt_events(events, n=8) -> str:
    rows = []
    for e in events[:n]:
        row = f"ev{e.event_id} {e.process_name or e.action} pid={e.process_pid}"
        if e.process_parent:
            row += f" parent={e.process_parent}"
        if e.command_line:
            row += f" cmd={e.command_line[:80]}"
        if e.destination_ip:
            row += f" -> {e.destination_ip}:{e.destination_port}"
        rows.append(row)
    return "\n".join(rows) or "(no events)"


def investigate(store, inc_id: str, llm, registry=None, seed=None,
                confidence_floor: float = 0.95,
                audit=None, controls=None,
                events=None) -> dict:
    """Drive TRIAGING -> RESPONSE_PLANNED -> policy decision. Shared core.

    audit: AuditRecorder or None (memory-only capture when None).
    controls: ControlState (§17) or None (unrestricted).
    events: explicit TelemetryEvent list (eval corpus); overrides
            registry-prefetch / synthetic fallback.
    """
    from aegis.agents.reasoning import PROMPT_VERSION, detect_injection, untrusted
    from aegis.agents.validation import validate_evidence
    from aegis.audit import version_manifest
    from aegis.intel import attack as attack_intel
    from aegis.intel.correlation import find_related
    from aegis.privacy import redact as privacy_redact
    from aegis.tools.registry import TOOL_SCHEMA_VERSION

    def untrusted_privacy(text: str) -> tuple[str, list[str]]:
        """§27 privacy-filtering step: mask secrets/PII before AI-visible views."""
        return privacy_redact(text)

    orch = Orchestrator(store)
    inc = store.get(inc_id)
    host = inc.fields.get("host", "unknown")
    orch.transition(inc_id, IncidentState.TRIAGING, "orchestrator", "slice start")

    summary_text = f"Incident type {inc.type} on {host}"
    cmd_kinds: list[str] = []
    if seed is not None:
        masked_cmd, cmd_kinds = untrusted_privacy(seed.command_line[:120])
        summary_text = (
            f"{seed.process_parent or 'unknown parent'} spawned "
            f"{seed.process_name} (pid {seed.process_pid}) on {host} at "
            f"{seed.ts.isoformat()}; cmd={untrusted(masked_cmd)}"
        )
    elif inc.fields.get("command_line"):
        masked_cmd, cmd_kinds = untrusted_privacy(str(inc.fields["command_line"])[:120])
        summary_text = (
            f"{inc.fields.get('parent', 'unknown parent')} spawned "
            f"{inc.fields.get('process', 'unknown process')} on {host}; "
            f"cmd={untrusted(masked_cmd)}"
        )

    # evidence: prefetch through the registry (agentic mode agents also fetch
    # their own); explicit events override (eval corpus); else canned story.
    if events is not None:
        evidence_events = list(events)
    elif registry is not None:
        proc_tree = registry.call("get_process_tree", "A2", host=host)
        net = registry.call("get_network_connections", "A2", host=host)
        evidence_events = list(proc_tree) + list(net)
    else:
        evidence_events = _synthetic_events(host)

    for ev in evidence_from_tool_result(inc_id, "read_tools", evidence_events):
        store.add_evidence(ev)

    # §15: flag suspicious instruction patterns found in untrusted inputs.
    # Scan RAW content only — summary_text embeds our own untrusted markers,
    # which the detector must not self-flag.
    injection_flags = list(detect_injection(
        inc.fields.get("command_line", "") or ""))
    for e in evidence_events:
        for field_val in (e.command_line, e.file_path):
            if field_val:
                injection_flags.extend(detect_injection(field_val))
    if audit is not None:
        for pat in set(injection_flags):
            audit.record("injection_flag", inc_id, actor="telemetry",
                         pattern=pat)
        if cmd_kinds:
            audit.record("privacy_redaction", inc_id, actor="privacy_gateway",
                         where="incident_summary", kinds=cmd_kinds,
                         reason="secrets/PII masked before AI-visible view")

    related = find_related(store, inc_id)
    corr_text = "\n".join(
        f"{r['incident_id']} shares: {', '.join(r['shared'])}" for r in related
    ) or "(no related incidents)"

    cand = attack_intel.match_keywords(f"{summary_text}")
    atk_text = "; ".join(f"{c['id']} {c['name']} [{c['tactic']}]" for c in cand) or "(none)"

    tool_calls = {
        "A1": "",
        "A2": "",
        "A3": f"correlation across incidents:\n{corr_text}",
        "A4": f"ATT&CK keyword candidates: {atk_text}",
        "A5": "",
    }

    pipe = AgentPipeline(llm, registry=registry, controls=controls)
    steps, results = pipe.run(
        {"incident_id": inc_id, "host": host, "type": inc.type,
         "summary": summary_text},
        tool_calls,
    )

    # §15 hallucinated-evidence defense: strip fabricated evidence_ids
    validation_report = validate_evidence(store, inc_id, results)

    # audit + step-record persistence (#4/#5)
    if audit is not None:
        for s in steps:
            audit.record("pipeline_stage", inc_id, actor=s.agent,
                         ok=s.ok, degraded=s.degraded, elapsed_ms=s.elapsed_ms,
                         error=s.error)
        for c in getattr(registry, "calls", []) or []:
            audit.record("tool_call", inc_id, actor=c["agent"],
                         tool=c["tool"], ok=c["ok"], error=c["error"])
        if injection_flags:
            audit.record("injection_flag", inc_id, actor="telemetry",
                         patterns=sorted(set(injection_flags)))
        if validation_report:
            audit.record("evidence_validation", inc_id, actor="validator",
                         report=validation_report)
    for s in steps:
        store.add_record("agentrun", inc_id, vars(s))
    for c in getattr(registry, "calls", []) or []:
        store.add_record("toolcall", inc_id, c)

    if any(not s.ok for s in steps):
        orch.transition(inc_id, IncidentState.ESCALATED,
                        "orchestrator", "pipeline degraded")
        errors = [f"{s.agent}: {s.error}" for s in steps if not s.ok]
        return {"ok": False, "errors": errors, "related": related,
                "evidence_count": len(evidence_events), "steps": steps}

    for to_state in (IncidentState.INVESTIGATING, IncidentState.CORRELATING,
                     IncidentState.ASSESSING, IncidentState.RESPONSE_PLANNED):
        orch.transition(inc_id, to_state, "orchestrator", "pipeline progress")

    confidence = confidence_floor
    a4 = results.get("A4")
    if a4 and isinstance(a4.data.get("confidence"), (int, float)):
        confidence = max(confidence, float(a4.data["confidence"]))

    facts = {"host": host, "confidence": confidence,
             "evidence_count": len(evidence_events)}
    decision = evaluate("isolate_host", facts)

    # §17 require-approval-for-all: even policy-ALLOW goes to the human gate
    if (controls is not None and controls.require_approval_all
            and decision.decision == Decision.ALLOW):
        decision = replace(decision, decision=Decision.APPROVE,
                           reason=f"{decision.reason}; operator requires approval for all actions")

    if audit is not None:
        audit.record("policy_decision", inc_id, actor="policy_engine",
                     action=decision.action, decision=decision.decision.value,
                     reason=decision.reason, policy_version=decision.policy_version)
    store.add_record("policy", inc_id, {
        "action": decision.action, "decision": decision.decision.value,
        "reason": decision.reason, "policy_version": decision.policy_version,
    })
    manifest = version_manifest(
        model=getattr(llm, "model_tag", "fake"),
        prompt_version=PROMPT_VERSION,
        policy_versions=[decision.policy_version],
        tool_schema_version=TOOL_SCHEMA_VERSION,
    )
    store.add_record("manifest", inc_id, manifest)

    if decision.decision == Decision.DENY:
        orch.transition(inc_id, IncidentState.FAILED,
                        "orchestrator", decision.reason)
    elif decision.decision == Decision.APPROVE:
        orch.transition(inc_id, IncidentState.AWAITING_APPROVAL,
                        "orchestrator", "human approval required")
    else:
        orch.transition(inc_id, IncidentState.AUTHORIZED,
                        "orchestrator", "auto-allow by policy")

    return {"ok": True, "decision": decision, "steps": steps,
            "results": results, "related": related,
            "evidence_count": len(evidence_events),
            "validation": validation_report, "manifest": manifest}


def execute_and_verify(store, inc_id: str, host: str,
                       max_retries: int = 2, controls=None) -> list:
    """AUTHORIZED -> EXECUTING -> VERIFYING -> RESOLVED | ESCALATED.

    Execution goes through the response-tool registry gate (#7): D1
    authorization + operator revocations apply.
    """
    from aegis.tools.registry import build_response_tools

    orch = Orchestrator(store)
    ex = SimulatedExecutor()
    vf = SimulatedVerifier(ex, max_retries=max_retries)
    reg = build_response_tools(ex, controls=controls)

    orch.transition(inc_id, IncidentState.EXECUTING, "orchestrator", "execute")
    reg.call("isolate_host", "D1", host=host, incident_id=inc_id)
    orch.transition(inc_id, IncidentState.VERIFYING, "orchestrator", "verify")

    verifications = []
    while True:
        v = vf.verify_host_isolated(host, inc_id)
        verifications.append(v)
        store.add_record("verification", inc_id, {
            "action": v.action, "target": v.target, "expected": v.expected,
            "actual": v.actual, "passed": v.passed,
        })
        nxt = vf.next_state(v)
        orch.transition(inc_id, nxt, "orchestrator", f"verify {v.actual}")
        if nxt in (IncidentState.RESOLVED, IncidentState.ESCALATED):
            return verifications
        orch.transition(inc_id, IncidentState.INVESTIGATING,
                        "orchestrator", "reopen")


def run_full_slice(host: str = "win-vm", llm_mode: str = "real",
                   confidence: float = 0.95, evidence_count: int = 4,
                   max_retries: int = 2, telemetry_mode: str = "synthetic",
                   controls=None) -> dict:
    """Full PowerShell slice: NEW -> ... -> RESOLVED/FAILED/ESCALATED.

    evidence_count kept for CLI/test signature compat; real count derives
    from persisted events.
    """
    from aegis.audit import AuditRecorder
    from aegis.controls import ControlState

    if controls is None:
        controls = ControlState.from_env()
    if controls.autonomy_blocked():
        return {"incident": None, "steps": [], "errors": [
            "autonomy paused by operator (§17)"], "related": [],
            "evidence_count": 0, "trace": []}

    llm = FakeLLM() if llm_mode == "fake" else _real_llm()
    reg = None
    seed = None
    es = None
    if telemetry_mode == "real":
        from aegis.tools.registry import build_read_tools

        es, tel = live_telemetry()
        reg = build_read_tools(tel, controls=controls)
        candidates = tel.search_events(host=host, event_id="1", limit=5)
        if not candidates:
            es.close()
            raise RuntimeError(f"no process-create events for host {host!r} in ES")
        seed = next((e for e in candidates if e.command_line), candidates[0])
        # es stays open: registry's tel serves agent tool calls during investigate

    store, store_es = make_store()

    audit_rec = AuditRecorder(es=store_es)
    audit_rec.ensure_index()

    try:
        orch = Orchestrator(store)

        alert_fields = {"severity": "high", "host": host}
        if seed is not None:
            alert_fields.update({
                "process": seed.process_name, "pid": seed.process_pid,
                "parent": seed.process_parent, "command_line": seed.command_line,
            })
        inc = ingest_alert(store, source="winlogbeat" if seed else "synthetic",
                           fields=alert_fields, incident_type="powershell")

        res = investigate(store, inc.id, llm, registry=reg, seed=seed,
                          confidence_floor=confidence, audit=audit_rec,
                          controls=controls)
    finally:
        if es is not None:
            es.close()

    out = {"incident": store.get(inc.id), "steps": res["steps"],
           "related": res["related"], "evidence_count": res["evidence_count"],
           "validation": res.get("validation", {}),
           "manifest": res.get("manifest", {}),
           "trace": [t.to_state.value for t in store.transitions(inc.id)]}

    if not res["ok"]:
        out["errors"] = res.get("errors", [])
        return out

    out["decision"] = res["decision"]
    if res["decision"].decision == Decision.DENY:
        return out

    if store.get(inc.id).state == IncidentState.AWAITING_APPROVAL:
        orch.transition(inc.id, IncidentState.AUTHORIZED,
                        "operator", "approved (slice)")
    out["verifications"] = execute_and_verify(store, inc.id, host,
                                              max_retries=max_retries,
                                              controls=controls)
    out["trace"] = [t.to_state.value for t in store.transitions(inc.id)]
    return out


def _real_llm():
    from aegis.config import get_settings

    s = get_settings()
    return LLMClient(s.llm_base_url, s.llm_model)