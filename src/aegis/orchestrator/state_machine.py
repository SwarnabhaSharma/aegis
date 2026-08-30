"""State machine: plain dict transition table, zero deps (ADR-018).

Authority (Phase C K.2): orchestrator drives most transitions; operator owns
approval/denial and emergency controls. LLM agents can never mutate state.
"""


from aegis.incidents.schema import IncidentState

ORCHESTRATOR = "orchestrator"
OPERATOR = "operator"

# actor -> {from_state -> set(to_state)}
_TRANSITIONS: dict[str, dict[IncidentState, frozenset[IncidentState]]] = {
    ORCHESTRATOR: {
        IncidentState.NEW: frozenset({IncidentState.TRIAGING}),
        IncidentState.TRIAGING: frozenset(
            {IncidentState.INVESTIGATING, IncidentState.RESOLVED}
        ),
        IncidentState.INVESTIGATING: frozenset({IncidentState.CORRELATING}),
        IncidentState.CORRELATING: frozenset({IncidentState.ASSESSING}),
        IncidentState.ASSESSING: frozenset({IncidentState.RESPONSE_PLANNED}),
        IncidentState.RESPONSE_PLANNED: frozenset(
            {IncidentState.AWAITING_APPROVAL, IncidentState.AUTHORIZED}
        ),
        IncidentState.AUTHORIZED: frozenset({IncidentState.EXECUTING}),
        IncidentState.EXECUTING: frozenset({IncidentState.VERIFYING}),
        IncidentState.VERIFYING: frozenset(
            {IncidentState.RESOLVED, IncidentState.REOPENED}
        ),
        IncidentState.REOPENED: frozenset({IncidentState.INVESTIGATING}),
    },
    OPERATOR: {
        IncidentState.AWAITING_APPROVAL: frozenset(
            {IncidentState.AUTHORIZED, IncidentState.RESOLVED}
        ),
        IncidentState.VERIFYING: frozenset({IncidentState.REOPENED}),
        # §17 operator can cancel from any in-progress state
        IncidentState.INVESTIGATING: frozenset({IncidentState.CANCELLED}),
        IncidentState.CORRELATING: frozenset({IncidentState.CANCELLED}),
        IncidentState.ASSESSING: frozenset({IncidentState.CANCELLED}),
        IncidentState.RESPONSE_PLANNED: frozenset({IncidentState.CANCELLED}),
        IncidentState.EXECUTING: frozenset({IncidentState.CANCELLED}),
    },
}

# any-state fail-safe targets
_ANY_STATE_ESCALATE = {IncidentState.ESCALATED, IncidentState.FAILED}


class InvalidTransition(ValueError):
    """Raised when actor/state pair is not permitted."""


def can_transition(
    actor: str, from_state: IncidentState, to_state: IncidentState
) -> bool:
    if to_state in _ANY_STATE_ESCALATE:
        return actor in (ORCHESTRATOR, OPERATOR)
    allowed = _TRANSITIONS.get(actor, {}).get(from_state, frozenset())
    return to_state in allowed


def assert_transition(actor: str, from_state: IncidentState, to_state: IncidentState) -> None:
    if not can_transition(actor, from_state, to_state):
        raise InvalidTransition(
            f"{actor} cannot move {from_state.value} -> {to_state.value}"
        )


def valid_targets(actor: str, from_state: IncidentState) -> set[IncidentState]:
    targets = set(_TRANSITIONS.get(actor, {}).get(from_state, frozenset()))
    if actor in (ORCHESTRATOR, OPERATOR):
        targets |= _ANY_STATE_ESCALATE
    return targets
