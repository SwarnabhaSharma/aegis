"""Conditional permissions (WP-B, spec §11).

PermissionContext = situational facts at call time (incident state,
confidence, asset criticality, time, environment). Tools declare optional
`requires` predicates; the registry enforces them per call. Dimensions:
incident-state, confidence, asset-criticality, time-of-day, environment.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from aegis.incidents.schema import IncidentState

_STATE_ORDER: dict[str, int] = {
    s.value: i for i, s in enumerate(IncidentState)
}


@dataclass
class PermissionContext:
    incident_state: str = ""
    confidence: float = 0.0
    asset_criticality: str = "unknown"
    time_of_day: str = field(default_factory=lambda: datetime.now(UTC).strftime("%H:%M"))
    environment: str = "production"

    def satisfies(self, requires: dict) -> tuple[bool, str]:
        if "min_state" in requires:
            have = _STATE_ORDER.get(self.incident_state, -1)
            need = _STATE_ORDER.get(requires["min_state"], 99)
            if have < need:
                return False, f"state {self.incident_state or '?'} < {requires['min_state']}"
        if "min_confidence" in requires:
            if self.confidence < float(requires["min_confidence"]):
                return False, (f"confidence {self.confidence} < "
                               f"{requires['min_confidence']}")
        if "forbidden_criticality" in requires:
            if self.asset_criticality == requires["forbidden_criticality"]:
                return False, f"asset is {self.asset_criticality}"
        if "allowed_hours" in requires:
            start, end = requires["allowed_hours"]
            hour = int(self.time_of_day.split(":")[0])
            if not (start <= hour < end):
                return False, f"hour {hour} outside allowed window {start}-{end}"
        if "forbidden_environments" in requires:
            if self.environment in requires["forbidden_environments"]:
                return False, f"environment is {self.environment}"
        return True, ""


# agent -> the lifecycle state its stage represents (O.2 flow)
AGENT_STAGE_STATE = {
    "A1": "TRIAGING",
    "A2": "INVESTIGATING",
    "A3": "CORRELATING",
    "A4": "ASSESSING",
    "A5": "RESPONSE_PLANNED",
}