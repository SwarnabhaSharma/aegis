"""Local threat-intelligence store (Phase 7). Deterministic, offline.

Expanded from Phase 2's three hardcoded IPs: typed IOCs (ip/domain/hash)
with confidence + category. Rich result shape feeds A4 reasoning.
"""

import re

# value -> (ioc_type, confidence, category)
_IOC: dict[str, tuple[str, float, str]] = {
    "185.220.101.4": ("ip", 0.95, "c2"),
    "91.240.118.247": ("ip", 0.90, "scanner"),
    "45.155.205.233": ("ip", 0.92, "c2"),
    "193.106.191.35": ("ip", 0.85, "bruteforce"),
    "cdn-update-check.com": ("domain", 0.88, "malware-distribution"),
    "secure-login-verify.net": ("domain", 0.90, "phishing"),
    "a3f8d2e91c4b7f60d21e8a54c9b03f77d6e5a2c81b94f0d37e6c25a48f19b302": (
        "hash", 0.93, "payload.dll",
    ),
    "b7e23ec29af22b0b4e41da31e868d57226121c84": ("hash", 0.87, "dropper"),
}

_RE_SHA = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")
_RE_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def classify(value: str) -> str:
    v = value.strip().lower()
    if _RE_SHA.match(v):
        return "hash"
    if _RE_IP.match(v):
        return "ip"
    if "." in v and "/" not in v and "@" not in v:
        return "domain"
    return "unknown"


def lookup(value: str) -> dict:
    """Rich TI result for one indicator (any supported type)."""
    v = value.strip().lower()
    entry = _IOC.get(v)
    return {
        "value": v,
        "ioc_type": classify(v),
        "known_malicious": entry is not None,
        "confidence": entry[1] if entry else 0.0,
        "category": entry[2] if entry else "",
        "source": "local-intel-v2",
    }


def lookup_all(values: list[str]) -> list[dict]:
    return [lookup(v) for v in values]