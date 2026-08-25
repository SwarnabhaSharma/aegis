"""Conditional permissions (WP-B, spec §11).

PermissionContext = situational facts at call time (incident state,
confidence, asset criticality). Tools declare optional `requires`
predicates; the registry enforces them per call. Dimensions implemented:
incident-state, confidence, asset-criticality. Time/environment deferred
(single-operator dev scale; documented in gap-audit).
"""

from dataclasses import dataclass

from aegis.incidents.schema import IncidentState

_STATE_ORDER: dict[str, int] = {
    s.value: i for i, s in enumerate(IncidentState)
}


@dataclass
class PermissionContext:
    incident_state: str = ""
    confidence: float = 0.0
    asset_criticality: str = "unknown"

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
        return True, ""


# agent -> the lifecycle state its stage represents (O.2 flow)
AGENT_STAGE_STATE = {
    "A1": "TRIAGING",
    "A2": "INVESTIGATING",
    "A3": "CORRELATING",
    "A4": "ASSESSING",
    "A5": "RESPONSE_PLANNED",
}