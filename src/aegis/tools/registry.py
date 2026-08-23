"""Tool registry (Phase 2). Typed contracts, risk classes, allowed agents.

Registry is the single gate for which agent may call which tool (D-003/004).
Read tools = risk READ, allowed to reasoning agents. Response/verify tools
added in Phases 5-6, restricted to D1/D2.
"""

from dataclasses import dataclass

from aegis.intel import ti
from aegis.policies.store import get_policy_for
from aegis.tools.telemetry import TelemetrySource

READ = "READ"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"

TOOL_SCHEMA_VERSION = "1"  # §21: bump when any tool's input/output contract changes

# ponytail: _KNOWN_BAD retired — intel/ti.py local-intel-v2 store replaces it

# Phase C G.1: agents A1..A5
AGENT_TRIAGE = "A1"
AGENT_INVESTIGATION = "A2"
AGENT_CORRELATION = "A3"
AGENT_THREAT = "A4"
AGENT_PLANNER = "A5"

_REASONING_AGENTS = {
    AGENT_TRIAGE, AGENT_INVESTIGATION, AGENT_CORRELATION, AGENT_THREAT, AGENT_PLANNER
}


@dataclass
class Tool:
    name: str
    schema_in: dict
    risk_class: str
    reversible: bool
    allowed_agents: set[str]
    timeout_ms: int = 30000
    retry: str = "none"
    idempotent: bool = True
    audit: bool = True
    func: object = None
    spec: dict | None = None  # §16 ActionSpec: expected/verify/rollback/failure

    def authorized(self, agent: str) -> bool:
        return agent in self.allowed_agents


class ToolRegistry:
    def __init__(self, controls=None) -> None:
        self._tools: dict[str, Tool] = {}
        self.controls = controls  # ControlState; None = no runtime revocation
        self.calls: list[dict] = []  # every call attempt, ok or not (audit #4)

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def call(self, name: str, agent: str, **kwargs):
        entry = {"tool": name, "agent": agent, "args": kwargs,
                 "ok": False, "error": ""}
        self.calls.append(entry)
        try:
            tool = self._tools.get(name)
            if tool is None:
                raise KeyError(f"unknown tool: {name}")
            if self.controls is not None and name in self.controls.revoked_tools:
                raise PermissionError(f"{name} revoked by operator")
            if not tool.authorized(agent):
                raise PermissionError(f"{agent} not authorized for {name}")
            if tool.func is None:
                raise RuntimeError(f"{name} has no backend")
            result = tool.func(**kwargs)
            entry["ok"] = True
            return result
        except Exception as e:
            entry["error"] = str(e)
            raise

    def authorized_tools(self, agent: str) -> list[str]:
        return [n for n, t in self._tools.items() if t.authorized(agent)]


def build_verify_tools(verifier, controls=None) -> ToolRegistry:
    """Verify tools (Phase 6). Restricted to D2/verifier."""
    from aegis.verifier.verifier import SimulatedVerifier

    if not isinstance(verifier, SimulatedVerifier):
        raise TypeError("verifier must be SimulatedVerifier")
    reg = ToolRegistry(controls)
    reg.register(Tool(
        name="verify_host_isolated",
        schema_in={"host": str, "incident_id": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={"D2", "verifier"},
        func=lambda host, incident_id: verifier.verify_host_isolated(host, incident_id),
    ))
    reg.register(Tool(
        name="verify_process_terminated",
        schema_in={"host": str, "pid": str, "incident_id": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={"D2", "verifier"},
        func=lambda host, pid, incident_id: verifier.verify_process_terminated(
            host, pid, incident_id
        ),
    ))
    reg.register(Tool(
        name="verify_indicator_blocked",
        schema_in={"indicator": str, "incident_id": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={"D2", "verifier"},
        func=lambda indicator, incident_id: verifier.verify_indicator_blocked(
            indicator, incident_id
        ),
    ))
    reg.register(Tool(
        name="verify_persistence_removed",
        schema_in={"host": str, "incident_id": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={"D2", "verifier"},
        func=lambda host, incident_id: verifier.verify_persistence_removed(host, incident_id),
    ))
    return reg


def build_response_tools(executor, controls=None) -> ToolRegistry:
    """Response tools (Phase 5). Restricted to D1/executor — no reasoning agent may call."""
    from aegis.executor.executor import SimulatedExecutor  # local import avoids cycle

    if not isinstance(executor, SimulatedExecutor):
        raise TypeError("executor must be SimulatedExecutor")
    reg = ToolRegistry(controls)
    reg.register(Tool(
        name="isolate_host",
        schema_in={"host": str, "incident_id": str},
        risk_class=HIGH,
        reversible=False,
        allowed_agents={"D1", "executor"},
        spec={
            "expected_result": "host no longer communicates with external network",
            "verification_method": "verify_host_isolated",
            "rollback": "not supported (manual unisolation)",
            "failure_behavior": "REOPEN + escalate",
        },
        func=lambda host, incident_id, idempotency_key=None: executor.isolate_host(
            host, incident_id, idempotency_key
        ),
    ))
    reg.register(Tool(
        name="terminate_process",
        schema_in={"host": str, "pid": str, "incident_id": str},
        risk_class=MEDIUM,
        reversible=False,
        allowed_agents={"D1", "executor"},
        spec={
            "expected_result": "process no longer running on host",
            "verification_method": "verify_process_terminated",
            "rollback": "restart process manually",
            "failure_behavior": "REOPEN + escalate",
        },
        func=lambda host, pid, incident_id: executor.terminate_process(host, pid),
    ))
    reg.register(Tool(
        name="block_indicator",
        schema_in={"indicator": str, "incident_id": str},
        risk_class=MEDIUM,
        reversible=True,
        allowed_agents={"D1", "executor"},
        spec={
            "expected_result": "indicator blocked at egress",
            "verification_method": "verify_indicator_blocked",
            "rollback": "unblock indicator",
            "failure_behavior": "REOPEN + escalate",
        },
        func=lambda indicator, incident_id: executor.block_indicator(indicator),
    ))
    return reg


def build_read_tools(telemetry: TelemetrySource, controls=None) -> ToolRegistry:
    reg = ToolRegistry(controls)
    reg.register(Tool(
        name="search_events",
        schema_in={"host": str, "event_id": str, "process_name": str, "user": str, "limit": int},
        risk_class=READ,
        reversible=True,
        allowed_agents=_REASONING_AGENTS,
        func=lambda **kw: [e for e in telemetry.search_events(**kw)],
    ))
    reg.register(Tool(
        name="get_process_tree",
        schema_in={"host": str, "pid": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={AGENT_INVESTIGATION, AGENT_CORRELATION},
        func=lambda **kw: [e for e in telemetry.get_process_tree(**kw)],
    ))
    reg.register(Tool(
        name="get_network_connections",
        schema_in={"host": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={AGENT_INVESTIGATION, AGENT_CORRELATION},
        func=lambda **kw: [e for e in telemetry.get_network_connections(**kw)],
    ))
    reg.register(Tool(
        name="get_file_activity",
        schema_in={"host": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={AGENT_INVESTIGATION, AGENT_CORRELATION},
        func=lambda host, limit=100: [e for e in telemetry.get_file_activity(host, limit)],
    ))
    reg.register(Tool(
        name="get_authentication_events",
        schema_in={"host": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={AGENT_INVESTIGATION, AGENT_THREAT},
        func=lambda host, limit=100: [e for e in telemetry.get_authentication_events(host, limit)],
    ))
    reg.register(Tool(
        name="get_host_details",
        schema_in={"host": str},
        risk_class=READ,
        reversible=True,
        allowed_agents=_REASONING_AGENTS,
        func=lambda host: telemetry.get_host_details(host),
    ))
    reg.register(Tool(
        name="lookup_ip",
        schema_in={"ip": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={AGENT_THREAT, AGENT_INVESTIGATION},
        func=lambda ip: ti.lookup(ip),
    ))
    reg.register(Tool(
        name="lookup_hash",
        schema_in={"value": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={AGENT_THREAT},
        func=lambda value: ti.lookup(value),
    ))
    reg.register(Tool(
        name="lookup_domain",
        schema_in={"value": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={AGENT_THREAT},
        func=lambda value: ti.lookup(value),
    ))
    reg.register(Tool(
        name="get_policy",
        schema_in={"incident_type": str},
        risk_class=READ,
        reversible=True,
        allowed_agents={AGENT_PLANNER, AGENT_INVESTIGATION},
        func=lambda incident_type: [p for p in get_policy_for(incident_type)],
    ))
    return reg
