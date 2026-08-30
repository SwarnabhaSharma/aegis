"""Tests for privacy gateway (§10)."""
from aegis.privacy import RoleView, TokenVault, task_view, withheld_keys
from aegis.privacy.gateway import Gateway, get_gateway

# -- task_view --

class FakeEvent:
    def __init__(self, event_id, host="h"):
        self.event_id = event_id
        self.host = host
        self.command_line = "test"


def test_task_view_a1_sees_nothing():
    events = [FakeEvent("1"), FakeEvent("3"), FakeEvent("11")]
    result = task_view("A1", events)
    assert result == []


def test_task_view_a2_sees_all():
    events = [FakeEvent("1"), FakeEvent("3"), FakeEvent("11")]
    result = task_view("A2", events)
    assert len(result) == 3


def test_task_view_a4_sees_only_ioc_events():
    events = [FakeEvent("1"), FakeEvent("3"), FakeEvent("11"), FakeEvent("999")]
    result = task_view("A4", events)
    assert [e.event_id for e in result] == ["3", "11"]


def test_task_view_non_event_items_pass_through():
    policy = {"name": "block_on_high", "actions": ["isolate_host"]}
    events = [FakeEvent("1"), FakeEvent("3")]
    result = task_view("A1", [policy, *events])
    assert len(result) == 1
    assert result[0] == policy


def test_task_view_unknown_agent_sees_all():
    events = [FakeEvent("1"), FakeEvent("3")]
    result = task_view("UNKNOWN", events)
    assert len(result) == 2


# -- withheld_keys --

def test_withheld_keys_dict():
    obs = {"host": "x", "users": ["admin"], "seen": "2024-01-01"}
    result = withheld_keys("get_host_details", obs)
    assert "users" in result
    assert "host" not in result


def test_withheld_keys_list_returns_empty():
    result = withheld_keys("search_events", [FakeEvent("1")])
    assert result == []


def test_withheld_keys_unknown_tool_returns_empty():
    result = withheld_keys("unknown_tool", {"a": 1})
    assert result == []


# -- RoleView --

def test_role_view_ai_visible_filters():
    obs = {"host": "x", "users": ["admin"]}
    rv = RoleView("get_host_details", obs)
    visible = rv.ai_visible()
    assert "host" in visible
    assert "users" not in visible


def test_role_view_withheld():
    obs = {"host": "x", "users": ["admin"]}
    rv = RoleView("get_host_details", obs)
    assert rv.withheld() == ["users"]


def test_role_view_analyst_returns_raw():
    obs = {"host": "x", "users": ["admin"]}
    rv = RoleView("get_host_details", obs)
    assert rv.analyst() is obs


# -- TokenVault --

def test_tokenize_and_reveal():
    vault = TokenVault()
    text, tokens = vault.tokenize("email: admin@example.com")
    assert len(tokens) == 1
    assert "admin@example.com" not in text
    revealed = vault.reveal(text)
    assert revealed == "email: admin@example.com"


def test_tokenize_no_sensitive_data():
    vault = TokenVault()
    text, tokens = vault.tokenize("no secrets here")
    assert tokens == []
    assert text == "no secrets here"


def test_tokenize_empty():
    vault = TokenVault()
    text, tokens = vault.tokenize("")
    assert tokens == []
    assert text == ""


def test_vault_tokens_list():
    vault = TokenVault()
    vault.tokenize("user: test@test.com password=secret123")
    assert len(vault.tokens()) >= 2


# -- Gateway --

def test_gateway_filter_applies_task_view():
    gw = Gateway()
    events = [FakeEvent("1"), FakeEvent("3")]
    rv = gw.filter("A1", "search_events", events)
    assert rv.raw == []


def test_gateway_filter_dict_passes_through():
    gw = Gateway()
    obs = {"host": "x", "users": ["admin"]}
    rv = gw.filter("A1", "get_host_details", obs)
    assert rv.raw == obs


def test_gateway_analyst_view_tokenizes():
    gw = Gateway()
    view = gw.analyst_view("admin@example.com")
    assert "admin@example.com" not in view
    assert "TOK:" in view


def test_gateway_reveal():
    gw = Gateway()
    view = gw.analyst_view("admin@example.com")
    revealed = gw.reveal(view)
    assert revealed == "admin@example.com"


def test_gateway_withheld_report_dict():
    gw = Gateway()
    obs = {"host": "x", "users": ["admin"]}
    report = gw.withheld_report("A1", "get_host_details", obs)
    assert "users" in report["withheld_keys"]
    assert report["agent"] == "A1"


def test_gateway_withheld_report_task_filtered():
    gw = Gateway()
    events = [FakeEvent("1"), FakeEvent("3")]
    report = gw.withheld_report("A1", "search_events", events)
    assert report["task_filtered"] is True
    assert report["events_withheld"] == 2


def test_get_gateway_singleton():
    gw1 = get_gateway()
    gw2 = get_gateway()
    assert gw1 is gw2
