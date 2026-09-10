from __future__ import annotations

from dataclasses import replace
import copy
import pytest

from finality_ref.errors import VerificationFailed
from finality_ref.models import Decision
from .conftest import NOW, make_candidate, make_stack, resign_cap, resign_evidence


CANDIDATE_MUTATIONS = [
    ("act_id", "act-other"),
    ("act_class", "storage-write"),
    ("effect_class", "storage-write"),
    ("source", "agent-B"),
    ("destination", "https://evil.invalid/collect"),
    ("purpose", "diagnostic"),
    ("jurisdiction", "US"),
    ("policy_epoch", 8),
    ("nonce", "nonce-substitute"),
    ("issued_at_ns", NOW - 20_000),
    ("freshness_ns", 9_999_999_999),
    ("sink_id", "sink-B"),
    ("boundary_id", "boundary-B"),
    ("scope", ("SEND",)),
    ("runtime_evidence_digest", "runtime-other"),
    ("authority_context", {"model": "substituted", "session": "s-1"}),
]

@pytest.mark.parametrize("field,value", CANDIDATE_MUTATIONS)
def test_capability_cannot_move_to_mutated_candidate(field, value):
    c, _, _, _, authority, effector, sink = make_stack()
    cap = authority.authorize(c)
    mutated = replace(c, **{field: value})
    with pytest.raises(VerificationFailed):
        sink.effectuate(mutated, cap)
    assert not effector.records


PAYLOAD_MUTATIONS = [
    {"amount_minor": 1001, "currency": "EUR", "beneficiary": "B1"},
    {"amount_minor": 1000, "currency": "USD", "beneficiary": "B1"},
    {"amount_minor": 1000, "currency": "EUR", "beneficiary": "B2"},
    {"amount_minor": 1000, "currency": "EUR"},
    {"amount_minor": 1000, "currency": "EUR", "beneficiary": "B1", "extra": True},
    {"amount_minor": -1000, "currency": "EUR", "beneficiary": "B1"},
    {"amount_minor": 0, "currency": "EUR", "beneficiary": "B1"},
    {"amount_minor": 2**63-1, "currency": "EUR", "beneficiary": "B1"},
    {"amount_minor": 1000, "currency": "EUR", "beneficiary": "B1", "memo": "x"},
    {"amount_minor": 1000, "currency": "EUR", "beneficiary": "B1", "memo": "é"},
    {"amount_minor": 1000, "currency": "EUR", "beneficiary": ["B1"]},
    {"amount_minor": [1000], "currency": "EUR", "beneficiary": "B1"},
    {"amount_minor": 1000, "currency": ["EUR"], "beneficiary": "B1"},
    {"amount_minor": 1000, "currency": "EUR", "beneficiary": {"id": "B1"}},
    {"amount_minor": 1000, "currency": "EUR", "beneficiary": "B1", "nested": {"x": 1}},
    {"amount_minor": 1000, "currency": "EUR", "beneficiary": "B1", "nested": {"x": 2}},
    {"amount_minor": 1000, "currency": "EUR", "beneficiary": "B1", "list": [1,2,3]},
    {"amount_minor": 1000, "currency": "EUR", "beneficiary": "B1", "list": [3,2,1]},
    {"amount_minor": 1000, "currency": "eur", "beneficiary": "B1"},
    {"amount_minor": 1000, "currency": "EUR ", "beneficiary": "B1"},
]

@pytest.mark.parametrize("payload", PAYLOAD_MUTATIONS)
def test_payload_substitution_detected(payload):
    c, _, _, _, authority, effector, sink = make_stack()
    cap = authority.authorize(c)
    with pytest.raises(VerificationFailed):
        sink.effectuate(replace(c, payload=payload), cap)
    assert not effector.records


CAP_MUTATIONS = [
    ("authority_id", "authority-B"),
    ("candidate_digest", "0" * 64),
    ("descriptor_digest", "1" * 64),
    ("sink_id", "sink-B"),
    ("boundary_id", "boundary-B"),
    ("nonce", "nonce-other"),
    ("scope", ("SEND",)),
    ("policy_epoch", 8),
    ("evidence_id", "2" * 64),
    ("transition_id", "3" * 64),
    ("issued_at_ns", NOW + 2_000_000_000),
    ("expires_at_ns", NOW - 1),
    ("key_id", "other-key"),
]

@pytest.mark.parametrize("field,value", CAP_MUTATIONS)
def test_signed_but_structurally_inconsistent_capability_rejected(field, value):
    c, authn, _, _, authority, effector, sink = make_stack()
    cap = authority.authorize(c)
    # Re-sign most mutations to show rejection is not merely signature checking.
    if field == "key_id":
        bad = replace(cap, **{field: value})
    else:
        bad = resign_cap(cap, authn, **{field: value})
    with pytest.raises(VerificationFailed):
        sink.effectuate(c, bad)
    assert not effector.records


EVIDENCE_MUTATIONS = [
    ("authority_id", "authority-B"),
    ("descriptor_digest", "4" * 64),
    ("candidate_digest", "5" * 64),
    ("transition_id", "6" * 64),
    ("policy_epoch", 8),
    ("decision", Decision.DENY),
    ("committed_at_ns", NOW + 999),
]

@pytest.mark.parametrize("field,value", EVIDENCE_MUTATIONS)
def test_resigned_evidence_substitution_rejected(field, value):
    c, authn, evidence_store, _, authority, effector, sink = make_stack()
    cap = authority.authorize(c)
    original = evidence_store.get(cap.evidence_id)
    assert original is not None
    bad = resign_evidence(original, authn, **{field: value})
    evidence_store.replace_for_adversarial_test(bad)
    # committed_at_ns is deliberately not currently a capability binding; changing
    # only it is signature-valid and semantically harmless to authorization.
    if field == "committed_at_ns":
        receipt = sink.effectuate(c, cap)
        assert receipt.effect_status == "EFFECTIVE"
    else:
        with pytest.raises(VerificationFailed):
            sink.effectuate(c, cap)
        assert not effector.records


@pytest.mark.parametrize("sig", [
    "", "0", "00" * 32, "ff" * 32, "deadbeef", "g" * 64,
    "a" * 63, "a" * 65, "\x00" * 32, "not-a-signature",
])
def test_capability_signature_corruption(sig):
    c, _, _, _, authority, effector, sink = make_stack()
    cap = authority.authorize(c)
    bad = replace(cap, signature=sig)
    with pytest.raises(VerificationFailed):
        sink.effectuate(c, bad)
    assert not effector.records
