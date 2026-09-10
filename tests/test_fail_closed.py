from __future__ import annotations

from dataclasses import replace
import pytest

from finality_ref.errors import EffectDenied, EvidenceError, ReplayDetected, VerificationFailed
from .conftest import NOW, make_stack, resign_cap


def test_evidence_store_failure_produces_no_capability_and_burns_nonce():
    c, _, evidence, state, authority, eff, sink = make_stack()
    evidence.fail_commits = True
    with pytest.raises(EvidenceError):
        authority.authorize(c)
    assert not eff.records
    evidence.fail_commits = False
    with pytest.raises(ReplayDetected):
        authority.authorize(c)


@pytest.mark.parametrize("field,value", [
    ("signature", "bad"),
    ("candidate_digest", "0"*64),
    ("descriptor_digest", "1"*64),
    ("evidence_id", "2"*64),
    ("transition_id", "3"*64),
])
def test_verification_failure_never_claims_or_effects(field, value):
    c, authn, _, _, authority, eff, sink = make_stack()
    cap = authority.authorize(c)
    if field == "signature":
        bad = replace(cap, signature=value)
    else:
        bad = resign_cap(cap, authn, **{field:value})
    with pytest.raises(VerificationFailed):
        sink.effectuate(c, bad)
    assert not eff.records
    assert not sink.consumption_store.is_claimed(cap.capability_id)


@pytest.mark.parametrize("fail_count", [1,2,3,5,10])
def test_downstream_failure_never_allows_same_capability_retry(fail_count):
    c, _, _, _, authority, eff, sink = make_stack()
    cap = authority.authorize(c)
    eff.fail_next = True
    with pytest.raises(EffectDenied):
        sink.effectuate(c, cap)
    for _ in range(fail_count):
        with pytest.raises(ReplayDetected):
            sink.effectuate(c, cap)
    assert not eff.records


@pytest.mark.parametrize("delta", [1, 1000, 1_000_000, 1_000_000_000, 10_000_000_000])
def test_capability_cannot_be_extended_beyond_candidate_freshness(delta):
    c, authn, _, _, authority, eff, sink = make_stack()
    cap = authority.authorize(c)
    too_long = c.issued_at_ns + c.freshness_ns + delta
    bad = resign_cap(cap, authn, expires_at_ns=too_long)
    with pytest.raises(VerificationFailed):
        sink.effectuate(c, bad)
    assert not eff.records
