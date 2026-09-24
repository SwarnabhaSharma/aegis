"""Tests for operations priority scoring."""

from datetime import UTC, datetime, timedelta

from aegis.incidents.schema import Incident
from aegis.operations.priority import (
    _age_factor,
    _age_hours,
    rank_incidents,
    score_incident,
)


def _make_incident(severity="medium", host="win-vm", hours_ago=1.0):
    now = datetime.now(UTC)
    return Incident(
        id="inc-test",
        source_alert_id="alert-test",
        type="powershell",
        severity=severity,
        fields={"host": host},
        created_at=now - timedelta(hours=hours_ago),
    )


def test_age_hours():
    inc = _make_incident(hours_ago=3.0)
    age = _age_hours(inc, now=datetime.now(UTC))
    assert 2.9 < age < 3.1


def test_age_factor_tiers():
    assert _age_factor(0.0) == 1.0    # < 1hr
    assert _age_factor(0.5) == 1.0    # < 1hr
    assert _age_factor(1.0) == 2.0    # >= 1hr
    assert _age_factor(23.0) == 2.0   # < 24hr
    assert _age_factor(24.0) == 3.0   # >= 24hr
    assert _age_factor(167.0) == 3.0  # < 7d
    assert _age_factor(168.0) == 4.0  # >= 7d


def test_score_critical_beats_high():
    crit = _make_incident(severity="critical", hours_ago=1.0)
    high = _make_incident(severity="high", hours_ago=1.0)
    assert score_incident(crit) > score_incident(high)


def test_score_older_beats_newer():
    old = _make_incident(severity="medium", hours_ago=48.0)
    new = _make_incident(severity="medium", hours_ago=0.5)
    assert score_incident(old) > score_incident(new)


def test_score_critical_asset_beats_normal():
    crit_box = _make_incident(severity="medium", host="critical-box", hours_ago=1.0)
    normal = _make_incident(severity="medium", host="win-vm", hours_ago=1.0)
    assert score_incident(crit_box) > score_incident(normal)


def test_rank_incidents_order():
    incidents = [
        _make_incident(severity="low", hours_ago=1.0),
        _make_incident(severity="critical", hours_ago=24.0),
        _make_incident(severity="medium", hours_ago=1.0),
    ]
    ranked = rank_incidents(incidents)
    assert ranked[0].severity == "critical"
    assert ranked[-1].severity == "low"


def test_rank_incidents_empty():
    assert rank_incidents([]) == []
