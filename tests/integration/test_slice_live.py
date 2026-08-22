"""Live-ES slice integration. Opt-in: AEGIS_INTEGRATION=1.

Runs the PowerShell slice against real winlogbeat telemetry on the VM
(fake LLM — no llama.cpp dependency). Asserts seed + read tools + policy.
"""

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AEGIS_INTEGRATION") != "1",
    reason="live-ES integration; set AEGIS_INTEGRATION=1",
)


def test_slice_real_telemetry_resolves():
    import sys
    sys.path.insert(0, "scripts")
    from run_slice import run_slice

    from aegis.incidents.schema import IncidentState

    res = run_slice(host="swarnabhasharma", llm_mode="fake",
                    telemetry_mode="real")
    assert res["incident"].state == IncidentState.RESOLVED
    assert all(s.ok for s in res["steps"])
    assert res["verifications"][-1].passed is True


def test_slice_real_telemetry_missing_host_raises():
    import sys
    sys.path.insert(0, "scripts")
    from run_slice import run_slice

    with pytest.raises(RuntimeError, match="no process-create events"):
        run_slice(host="no-such-host", llm_mode="fake",
                  telemetry_mode="real")


def test_slice_es_mode_correlates_across_runs():
    """Two ES-store runs share IOC 185.220.101.4 -> second sees first."""
    import os
    import sys

    sys.path.insert(0, "scripts")
    from run_slice import run_slice

    from aegis.incidents.schema import IncidentState

    os.environ["AEGIS_STORE"] = "es"
    try:
        r1 = run_slice(host="win-vm", llm_mode="fake", telemetry_mode="synthetic")
        r2 = run_slice(host="win-vm", llm_mode="fake", telemetry_mode="synthetic")
    finally:
        os.environ.pop("AEGIS_STORE", None)
    assert r1["incident"].state == IncidentState.RESOLVED
    assert r2["incident"].state == IncidentState.RESOLVED
    assert r2["evidence_count"] >= 3
    related_ids = {r["incident_id"] for r in r2["related"]}
    assert r1["incident"].id in related_ids
