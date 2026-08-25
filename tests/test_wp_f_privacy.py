"""WP-F tests: task minimization, RoleViews, reversible tokenization vault."""

from aegis.privacy import RoleView, TokenVault, task_view
from aegis.tools.telemetry import TelemetryEvent


def _events():
    return [
        TelemetryEvent(event_id="1", channel="sysmon", action="ProcessCreate",
                       host="win-vm", process_name="notepad.exe"),
        TelemetryEvent(event_id="3", channel="sysmon", action="NetworkConnect",
                       host="win-vm", destination_ip="185.220.101.4"),
        TelemetryEvent(event_id="4624", channel="Security", action="Logon",
                       host="win-vm", user="alice"),
    ]


# -- §10 task-based minimization --

def test_task_view_a1_sees_nothing():
    assert task_view("A1", _events()) == []


def test_task_view_a4_sees_ioc_events_only():
    view = task_view("A4", _events())
    ids = {e.event_id for e in view}
    assert ids == {"3", "4624"}


def test_task_view_a2_full():
    assert len(task_view("A2", _events())) == 3


# -- RoleViews: AI vs analyst --

def test_roleview_ai_withholds_users_field():
    obs = {"host": "win-vm", "users": ["alice"], "event_count": 2}
    rv = RoleView("get_host_details", obs)
    ai = rv.ai_visible()
    assert "users" not in ai
    assert rv.analyst()["users"] == ["alice"]
    assert rv.withheld() == ["users"]


# -- reversible tokenization vault --

def test_vault_tokenize_and_reveal():
    vault = TokenVault()
    secret = "password=Hunter2Secret9"
    tokenized, tokens = vault.tokenize(f"cmd ran with {secret} flag")
    assert secret not in tokenized
    assert tokens and all(t.startswith("[TOK:") for t in tokens)
    revealed = vault.reveal(tokenized)
    # reversible: analyst reveal restores the ORIGINAL span exactly
    assert f"cmd ran with {secret} flag" == revealed
    assert vault.tokens()


def test_vault_two_incidents_isolated():
    v1, v2 = TokenVault(), TokenVault()
    t1, _ = v1.tokenize("password=Alpha12345")
    t2, _ = v2.tokenize("password=Bravo67890")
    # cross-reveal must not leak between incidents
    assert "Alpha" not in v2.reveal(t1)
    assert "Bravo" not in v1.reveal(t2)