from __future__ import annotations

from dataclasses import replace
import pytest

from finality_ref.errors import ValidationDenied
from finality_ref.models import ActStatus
from .conftest import NOW, make_candidate, make_policy, make_stack


DENIAL_CASES = [
    ("purpose", "unapproved", "purpose_not_allowed"),
    ("jurisdiction", "XX", "jurisdiction_not_allowed"),
    ("sink_id", "sink-X", "sink_not_allowed"),
    ("boundary_id", "boundary-X", "boundary_not_allowed"),
    ("effect_class", "unknown-effect", "effect_class_not_allowed"),
    ("policy_epoch", 8, "policy_epoch_mismatch"),
    ("scope", ("ROOT",), "scope_not_allowed"),
    ("scope", tuple(), "empty_scope"),
    ("scope", ("POST:/payments", "POST:/payments"), "duplicate_scope"),
    ("runtime_evidence_digest", "wrong", "runtime_evidence_mismatch"),
    ("freshness_ns", 0, "invalid_freshness"),
    ("issued_at_ns", NOW - 20_000_000_000, "candidate_stale"),
    ("issued_at_ns", NOW + 2_000_000_000, "candidate_from_future"),
    ("status", ActStatus.EFFECTIVE, "candidate_not_non_effective"),
]

@pytest.mark.parametrize("field,value,reason", DENIAL_CASES)
def test_policy_denial_matrix(field, value, reason):
    c = make_candidate(**{field: value})
    _, _, _, _, authority, _, _ = make_stack(c)
    with pytest.raises(ValidationDenied) as exc:
        authority.authorize(c)
    assert reason in str(exc.value)


@pytest.mark.parametrize("jurisdiction", ["EU", "US", "IN"])
@pytest.mark.parametrize("purpose", ["approved-purpose", "diagnostic", "render"])
def test_allowed_purpose_jurisdiction_cross_product(jurisdiction, purpose):
    c = make_candidate(jurisdiction=jurisdiction, purpose=purpose)
    *_, authority, _, _ = make_stack(c)
    assert authority.authorize(c)


@pytest.mark.parametrize("quota,budget,cost,allowed", [
    (1, 1, 1, True), (1, 2, 2, True), (2, 1, 1, True),
    (0, 1, 1, False), (1, 0, 1, False), (1, 1, 2, False),
    (5, 3, 3, True), (5, 3, 4, False),
])
def test_quota_budget_boundaries(quota, budget, cost, allowed):
    c, _, _, state, authority, _, _ = make_stack()
    state.configure_source(c.source, quota=quota, budget=budget)
    if allowed:
        assert authority.authorize(c, cost=cost)
    else:
        with pytest.raises(ValidationDenied):
            authority.authorize(c, cost=cost)


@pytest.mark.parametrize("revoked", ["agent-A", "agent-B", "", "service:123"])
def test_revocation_behavior(revoked):
    c = make_candidate(source=revoked or "agent-A")
    policy = make_policy(revoked_sources=frozenset({revoked}) if revoked else frozenset())
    *_, authority, _, _ = make_stack(c, policy=policy)
    if revoked:
        with pytest.raises(ValidationDenied):
            authority.authorize(c)
    else:
        assert authority.authorize(c)
