"""Mid-run cancellation tests (§17)."""
from aegis.agents.pipeline import AgentPipeline
from aegis.controls import ControlState
from aegis.incidents.schema import IncidentState
from aegis.orchestrator.state_machine import can_transition
from aegis.slice import FakeLLM


class FakeRegistry:
    def __init__(self, tools=None):
        self._tools = tools or []
        self.calls = []

    def authorized_tools(self, agent):
        return self._tools

    def call(self, name, agent, **kwargs):
        self.calls.append({"tool": name, "agent": agent, "args": kwargs})
        return []

    def set_permission_provider(self, fn):
        pass


# -- ControlState cancel --

def test_cancel_incident():
    ctl = ControlState()
    ctl.cancel_incident("inc-1")
    assert ctl.is_cancelled("inc-1")
    assert not ctl.is_cancelled("inc-2")


def test_uncancel_incident():
    ctl = ControlState()
    ctl.cancel_incident("inc-1")
    ctl.uncancel_incident("inc-1")
    assert not ctl.is_cancelled("inc-1")


# -- State transitions --

def test_cancel_from_investigating():
    assert can_transition("operator", IncidentState.INVESTIGATING,
                          IncidentState.CANCELLED)


def test_cancel_from_correlating():
    assert can_transition("operator", IncidentState.CORRELATING,
                          IncidentState.CANCELLED)


def test_cancel_from_executing():
    assert can_transition("operator", IncidentState.EXECUTING,
                          IncidentState.CANCELLED)


def test_cannot_cancel_from_resolved():
    assert not can_transition("operator", IncidentState.RESOLVED,
                              IncidentState.CANCELLED)


def test_cannot_cancel_from_new():
    assert not can_transition("operator", IncidentState.NEW,
                              IncidentState.CANCELLED)


def test_orchestrator_cannot_cancel():
    assert not can_transition("orchestrator", IncidentState.INVESTIGATING,
                              IncidentState.CANCELLED)


# -- Pipeline cancel --

def test_pipeline_cancel_stops_at_next_agent():
    ctl = ControlState()
    pipe = AgentPipeline(FakeLLM(), registry=FakeRegistry(), controls=ctl)
    summary = {"incident_id": "inc-1", "host": "h", "type": "t",
               "summary": "s"}
    tool_calls = {"A1": "", "A2": "", "A3": "", "A4": "", "A5": ""}

    # cancel before running
    ctl.cancel_incident("inc-1")
    steps, results = pipe.run(summary, tool_calls)

    # A1 should be the cancelled step
    assert len(steps) == 1
    assert steps[0].agent == "A1"
    assert steps[0].ok is False
    assert steps[0].error == "cancelled by operator"


def test_pipeline_cancel_midway():
    """Cancel after A1 runs — A2 should be the cancelled step."""
    ctl = ControlState()
    pipe = AgentPipeline(FakeLLM(), registry=FakeRegistry(), controls=ctl)
    summary = {"incident_id": "inc-1", "host": "h", "type": "t",
               "summary": "s"}
    tool_calls = {"A1": "", "A2": "", "A3": "", "A4": "", "A5": ""}

    # run A1 first, then cancel
    steps1, _ = pipe.run(summary, tool_calls)
    assert steps1[0].agent == "A1"

    ctl.cancel_incident("inc-1")
    steps2, _ = pipe.run(summary, tool_calls)
    assert steps2[0].agent == "A1"
    assert steps2[0].error == "cancelled by operator"


def test_pipeline_no_cancel_when_not_cancelled():
    ctl = ControlState()
    pipe = AgentPipeline(FakeLLM(), registry=FakeRegistry(), controls=ctl)
    summary = {"incident_id": "inc-1", "host": "h", "type": "t",
               "summary": "s"}
    tool_calls = {"A1": "", "A2": "", "A3": "", "A4": "", "A5": ""}
    steps, results = pipe.run(summary, tool_calls)
    # all 5 agents run
    assert len(steps) == 5
    assert all(s.ok for s in steps)
