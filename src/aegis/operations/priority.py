"""Alert priority scoring: severity × age × asset_criticality.

Score determines which alert the autonomous loop investigates next.
Higher score = higher priority.
"""

from __future__ import annotations

from datetime import UTC, datetime

from aegis.incidents.schema import Incident

# ponytail: hardcoded severity weights; swap for config when consumer exists.
SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
}

# ponytail: hardcoded asset criticality; mirrors policies.engine.ASSET_CRITICALITY.
ASSET_CRITICALITY: dict[str, str] = {"win-vm": "low", "critical-box": "critical"}

ASSET_WEIGHT: dict[str, float] = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 1.0,
}


def _age_hours(incident: Incident, now: datetime | None = None) -> float:
    now = now or datetime.now(UTC)
    delta = now - incident.created_at
    return max(delta.total_seconds() / 3600, 0.0)


def _age_factor(age_hours: float) -> float:
    """Tiered age bonus: +1 after 1hr, +2 after 24hr, +3 after 7d."""
    if age_hours >= 168:  # 7 days
        return 4.0  # base 1 + bonus 3
    if age_hours >= 24:
        return 3.0  # base 1 + bonus 2
    if age_hours >= 1:
        return 2.0  # base 1 + bonus 1
    return 1.0


def score_incident(incident: Incident, now: datetime | None = None) -> float:
    """Multiplicative priority: severity_weight × age_factor × asset_weight."""
    sev = SEVERITY_WEIGHT.get(incident.severity, 1.0)
    age = _age_factor(_age_hours(incident, now))
    host = incident.fields.get("host", "")
    asset_crit = ASSET_CRITICALITY.get(host, "medium")
    asset = ASSET_WEIGHT.get(asset_crit, 1.0)
    return sev * age * asset


def rank_incidents(incidents: list[Incident], now: datetime | None = None) -> list[Incident]:
    """Return incidents sorted by priority descending (highest score first)."""
    return sorted(incidents, key=lambda i: score_incident(i, now), reverse=True)
