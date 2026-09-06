"""Injection pattern detection on untrusted inputs (§15).

Extracted from slice.py investigate() to isolate the ~20-line scan +
audit-recording concern.
"""

from __future__ import annotations


def detect_and_record_injections(inc_id: str, fields: dict,
                                 evidence_events: list, audit=None) -> list[str]:
    """Scan command_line / file_path fields for injection patterns.

    Returns list of matched pattern strings. Records to audit when provided.
    """
    from aegis.agents.reasoning import detect_injection

    flags: list[str] = []

    cmdline = fields.get("command_line", "") or ""
    if cmdline:
        flags.extend(detect_injection(cmdline))

    for e in evidence_events:
        for field_val in (getattr(e, "command_line", None),
                          getattr(e, "file_path", None)):
            if field_val:
                flags.extend(detect_injection(field_val))

    if audit is not None:
        for pat in set(flags):
            audit.record("injection_flag", inc_id, actor="telemetry",
                         pattern=pat)

    return flags
