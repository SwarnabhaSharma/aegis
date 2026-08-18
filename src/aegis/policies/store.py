"""Policy store (Phase 4 skeleton). Deterministic YAML-ish policies per incident type.

Phase 4 builds the full policy engine (conditions, versioning, precedence).
Phase 2 only needs get_policy read tool to prove the flow.
"""

from dataclasses import dataclass


@dataclass
class Policy:
    action: str
    conditions: dict
    approval_required: bool
    risk_class: str
    version: str = "1.0"
    id: str = ""


_POLICIES: dict[str, list[Policy]] = {
    "powershell": [
        Policy(
            id="pol-powershell-isolate",
            action="isolate_host",
            conditions={
                "confidence": ">= 0.90",
                "asset_criticality": "!= critical",
                "evidence_count": ">= 3",
            },
            approval_required=False,
            risk_class="HIGH",
            version="1.0",
        )
    ]
}


def get_policy_for(incident_type: str) -> list[Policy]:
    return list(_POLICIES.get(incident_type, []))
