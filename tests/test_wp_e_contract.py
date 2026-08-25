"""WP-E tests: timeout, rate limit, safe retry, schema_out validation."""

import time

import pytest

from aegis.tools.registry import Tool, ToolRegistry


def _reg(tool: Tool) -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(tool)
    return reg


def test_timeout_enforced():
    def slow():
        time.sleep(2)
        return []

    t = Tool(name="slow", schema_in={}, risk_class="READ", reversible=True,
             allowed_agents={"A2"}, timeout_ms=100,
             schema_out="list", func=slow)
    with pytest.raises(RuntimeError, match="timed out"):
        _reg(t).call("slow", "A2")


def test_rate_limit_blocks_burst():
    t = Tool(name="rl", schema_in={}, risk_class="READ", reversible=True,
             allowed_agents={"A2"}, rate_limit=2,
             func=lambda: [])
    reg = _reg(t)
    reg.call("rl", "A2")
    time.sleep(0.05)
    reg.call("rl", "A2")
    start = time.monotonic()
    reg.call("rl", "A2")  # third within window -> bucket forces wait
    assert time.monotonic() - start > 0.5


def test_safe_retry_recovers_from_transient():
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("transient")
        return {"ok": True}

    t = Tool(name="flaky", schema_in={}, risk_class="READ", reversible=True,
             allowed_agents={"A2"}, retry="safe",
             schema_out="dict", func=flaky)
    r = _reg(t).call("flaky", "A2")
    assert r == {"ok": True}
    assert calls["n"] == 2


def test_retry_none_propagates_immediately():
    calls = {"n": 0}

    def always_fail():
        calls["n"] += 1
        raise ValueError("boom")

    t = Tool(name="f", schema_in={}, risk_class="READ", reversible=True,
             allowed_agents={"A2"}, retry="none", func=always_fail)
    with pytest.raises(ValueError, match="boom"):
        _reg(t).call("f", "A2")
    assert calls["n"] == 1


def test_schema_out_list_mismatch_rejected():
    t = Tool(name="bad", schema_in={}, risk_class="READ", reversible=True,
             allowed_agents={"A2"}, schema_out="list", func=lambda: {"x": 1})
    with pytest.raises(TypeError, match="expected list output"):
        _reg(t).call("bad", "A2")


def test_read_tools_declare_schema_and_spec():
    from aegis.tools.registry import build_read_tools
    from aegis.tools.telemetry import InMemoryTelemetry

    reg = build_read_tools(InMemoryTelemetry([]))
    for name in ("search_events", "get_process_tree", "get_network_connections",
                 "get_file_activity", "get_authentication_events"):
        tool = reg.get(name)
        assert tool.schema_out == "list", name
        assert tool.spec["expected_result"] == "read-only observation"
    hd = reg.get("get_host_details")
    assert hd.schema_out == "dict"
    gp = reg.get("get_policy")
    assert gp.schema_out == "list"


def test_timeout_thread_does_not_break_next_call():
    def slow_then_fast():
        if slow_then_fast.calls == 0:
            slow_then_fast.calls = 1
            time.sleep(1.5)
            return []
        return ["ok"]

    slow_then_fast.calls = 0
    t = Tool(name="stf", schema_in={}, risk_class="READ", reversible=True,
             allowed_agents={"A2"}, timeout_ms=200,
             schema_out="list", func=slow_then_fast)
    reg = _reg(t)
    with pytest.raises(RuntimeError, match="timed out"):
        reg.call("stf", "A2")  # worker still sleeping in background thread
    time.sleep(1.6)  # let the leaked worker finish (ponytail ceiling note)
    r = reg.call("stf", "A2")
    assert r == ["ok"]