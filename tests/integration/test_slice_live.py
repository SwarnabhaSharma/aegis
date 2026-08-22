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
