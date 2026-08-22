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

    def authorized(self, agent: str) -> bool:
        return agent in self.allowed_agents


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def call(self, name: str, agent: str, **kwargs):
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(f"unknown tool: {name}")
        if not tool.authorized(agent):
            raise PermissionError(f"{agent} not authorized for {name}")
        if tool.func is None:
            raise RuntimeError(f"{name} has no backend")
        return tool.func(**kwargs)

    def authorized_tools(self, agent: str) -> list[str]:
        return [n for n, t in self._tools.items() if t.authorized(agent)]


def build_verify_tools(verifier) -> ToolRegistry:
    """Verify tools (Phase 6). Restricted to D2/verifier."""
    from aegis.verifier.verifier import SimulatedVerifier

    if not isinstance(verifier, SimulatedVerifier):
        raise TypeError("verifier must be SimulatedVerifier")
    reg = ToolRegistry()
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


def build_response_tools(executor) -> ToolRegistry:
    """Response tools (Phase 5). Restricted to D1/executor — no reasoning agent may call."""
    from aegis.executor.executor import SimulatedExecutor  # local import avoids cycle

    if not isinstance(executor, SimulatedExecutor):
        raise TypeError("executor must be SimulatedExecutor")
    reg = ToolRegistry()
    reg.register(Tool(
        name="isolate_host",
        schema_in={"host": str, "incident_id": str, "idempotency_key": str},
        risk_class=HIGH,
        reversible=False,
        allowed_agents={"D1", "executor"},
        func=lambda host, incident_id, idempotency_key=None: executor.isolate_host(
            host, incident_id, idempotency_key
        ),
    ))
    return reg


def build_read_tools(telemetry: TelemetrySource) -> ToolRegistry:
    reg = ToolRegistry()
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
