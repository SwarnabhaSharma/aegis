"""Deterministic baseline classifier (spec §20 comparison, WP-H).

Pure pattern rules — no LLM. Serves as the measurable baseline the agent
pipeline is compared against in eval reports.
"""

from aegis.intel import attack as attack_intel
from aegis.privacy import detect as privacy_detect

_SUSPICIOUS_MARKERS = ("-enc ", "encodedcommand", "bypass", "-hidden",
                       "downloadstring", "minidump", "comsvcs.dll",
                       "net user", "ncat", "-e cmd")


def baseline_classify(alert_fields: dict, events: list) -> dict:
    """Rule-based judgment: {investigate, classification}."""
    text = (str(alert_fields.get("command_line", "")) + " "
            + str(alert_fields.get("process", ""))).lower()
    hits = sum(1 for m in _SUSPICIOUS_MARKERS if m in text)
    net_iocs = [e for e in events if getattr(e, "destination_ip", "")]
    sensitive = any(privacy_detect(str(getattr(e, "file_path", "")))
                    for e in events)

    score = hits * 2 + len(net_iocs)
    investigate = score > 0 or bool(net_iocs) or sensitive
    classification = ("malicious" if score >= 2
                      else "suspicious" if score == 1
                      else "benign")
    return {"investigate": investigate,
            "classification": classification,
            "marker_hits": hits}


def baseline_injection_flag(events: list) -> bool:
    from aegis.agents.reasoning import detect_injection

    for e in events:
        for val in (getattr(e, "command_line", ""), getattr(e, "file_path", "")):
            if val and detect_injection(val):
                return True
    return False


def attack_candidates(text: str) -> int:
    return len(attack_intel.match_keywords(text))