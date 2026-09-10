from __future__ import annotations

from dataclasses import replace
import pytest

from finality_ref.errors import EffectDenied, ReplayDetected, ValidationDenied, VerificationFailed
from finality_ref.models import ActStatus, Decision, build_hcad
from .conftest import NOW, make_candidate, make_stack


def test_candidate_starts_non_effective():
    assert make_candidate().status == ActStatus.NON_EFFECTIVE


def test_hcad_binds_payload_without_copying_payload():
    c = make_candidate()
    d = build_hcad(c)
    assert d.payload_digest == c.payload_digest()
    assert not hasattr(d, "payload")


def test_authority_commits_evidence_before_returning_capability(stack):
    c, _, evidence, _, authority, _, _ = stack
    cap = authority.authorize(c)
    ev = evidence.get(cap.evidence_id)
    assert ev is not None and ev.decision == Decision.ALLOW


def test_authority_advances_protected_state_before_capability(stack):
    c, _, _, state, authority, _, _ = stack
    before = state.snapshot(c.source)
    cap = authority.authorize(c)
    after = state.snapshot(c.source)
    assert after.version == before.version + 1
    assert after.quota == before.quota - 1
    assert state.verify_transition(cap.transition_id, c)


def test_valid_path_crosses_finality_boundary(stack):
    c, authn, _, _, authority, effector, sink = stack
    cap = authority.authorize(c)
    receipt = sink.effectuate(c, cap)
    assert receipt.effect_status == "EFFECTIVE"
    assert len(effector.records) == 1
    assert authn.verify(receipt.unsigned(), receipt.signature, receipt.key_id)


def test_direct_effector_use_is_denied(stack):
    c, _, _, _, _, effector, _ = stack
    with pytest.raises(EffectDenied):
        effector.direct_effect(c)
    assert not effector.records


def test_capability_single_use(stack):
    c, _, _, _, authority, effector, sink = stack
    cap = authority.authorize(c)
    sink.effectuate(c, cap)
    with pytest.raises(ReplayDetected):
        sink.effectuate(c, cap)
    assert len(effector.records) == 1


def test_duplicate_nonce_cannot_be_reauthorized(stack):
    c, _, _, _, authority, _, _ = stack
    authority.authorize(c)
    c2 = replace(c, act_id="another-act")
    with pytest.raises(ReplayDetected):
        authority.authorize(c2)


def test_policy_denial_releases_no_capability():
    c = make_candidate(purpose="forbidden")
    *_, authority, effector, sink = make_stack(c)
    with pytest.raises(ValidationDenied):
        authority.authorize(c)
    assert not effector.records


def test_effect_failure_burns_capability(stack):
    c, _, _, _, authority, effector, sink = stack
    cap = authority.authorize(c)
    effector.fail_next = True
    with pytest.raises(EffectDenied):
        sink.effectuate(c, cap)
    with pytest.raises(ReplayDetected):
        sink.effectuate(c, cap)
    assert not effector.records


def test_effective_candidate_cannot_be_represented_as_pending(stack):
    c, _, _, _, authority, _, sink = stack
    cap = authority.authorize(c)
    effective = replace(c, status=ActStatus.EFFECTIVE)
    with pytest.raises(VerificationFailed):
        sink.effectuate(effective, cap)
