"""T3 tests: privacy detection, redaction, AI-visible views, audit (§10/§27)."""

import sys

sys.path.insert(0, "scripts")

from aegis.incidents.evidence import evidence_from_tool_result
from aegis.privacy import ai_visible, classification_level, detect, redact, withheld_keys
from aegis.tools.telemetry import TelemetryEvent

# -- detection --

def test_detect_email():
    assert "email" in detect("contact alice@corp.example.com ASAP")


def test_detect_credential_kv():
    kinds = detect(
        "powershell -c $p='password=Hunter2Secret!' ; "
        "curl -H 'Authorization: Bearer xyz'")
    assert "credential" in kinds


def test_detect_aws_and_jwt():
    assert "aws_access_key" in detect("key AKIAIOSFODNN7EXAMPLE in config")
    assert "jwt" in detect("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4f")


def test_detect_ssn():
    assert "ssn" in detect("record 123-45-6789 filed")


def test_detect_clean_text():
    assert detect("powershell -enc SQBFAFA7AFIA normal") == []


# -- redaction --

def test_redact_masks_and_preserves_rest():
    masked, kinds = redact("mail bob@corp.com then dir C:\\Windows")
    assert "[REDACTED:email]" in masked
    assert "bob@corp.com" not in masked
    assert "dir C:\\Windows" in masked
    assert kinds == ["email"]


def test_redact_multiple_kinds():
    masked, kinds = redact("password=SuperSecret9 mail a@b.co")
    assert "[REDACTED:credential]" in masked
    assert "[REDACTED:email]" in masked
    assert set(kinds) == {"credential", "email"}


def test_classification_levels():
    assert classification_level(["email"]) == "pii"
    assert classification_level(["jwt"]) == "secret"
    assert classification_level([]) == "normal"


# -- evidence tagging (§27 slice privacy step) --

def test_evidence_tagged_secret_on_credential_cmd():
    ev = TelemetryEvent(event_id="1", channel="sysmon", action="ProcessCreate",
                        host="win-vm", process_name="powershell.exe",
                        command_line="powershell -c password=Hunter2Secret9")
    tagged = evidence_from_tool_result("inc-1", "t", [ev])
    assert tagged[0].classification == "secret"
    assert tagged[0].data["_privacy"]["kinds"] == ["credential"]


def test_evidence_normal_when_clean():
    ev = TelemetryEvent(event_id="1", channel="sysmon", action="ProcessCreate",
                        host="win-vm", process_name="notepad.exe",
                        command_line="notepad notes.txt")
    tagged = evidence_from_tool_result("inc-1", "t", [ev])
    assert tagged[0].classification == "normal"
    assert "_privacy" not in tagged[0].data


# -- AI-visible dict allowlist (§10 field-level control) --

def _host_details_dict():
    return {"host": "win-vm", "seen": True, "event_count": 5,
            "channels": ["sysmon"], "users": ["alice", "bob"]}


def test_ai_visible_strips_users():
    view = ai_visible("get_host_details", _host_details_dict())
    assert "users" not in view
    assert view["host"] == "win-vm"
    # analyst-facing original untouched
    assert _host_details_dict()["users"] == ["alice", "bob"]


def test_withheld_keys_reported():
    assert withheld_keys("get_host_details", _host_details_dict()) == ["users"]
    assert withheld_keys("get_process_tree", {}) == []


def test_ai_visible_passthrough_for_lists():
    obs = [{"event_id": "1"}]
    assert ai_visible("get_process_tree", obs) is obs


# -- observation masking through reasoning helper --

def test_fmt_observation_masks_secrets():
    from aegis.agents.reasoning import _fmt_observation

    ev = TelemetryEvent(event_id="1", channel="sysmon", action="ProcessCreate",
                        host="win-vm", process_name="powershell.exe",
                        command_line="powershell -c password=Hunter2Secret9")
    out = _fmt_observation([ev], tool="get_process_tree")
    assert "Hunter2Secret9" not in out
    assert "[REDACTED:credential]" in out