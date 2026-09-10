from __future__ import annotations

from dataclasses import replace
import pytest

from finality_ref.crypto import HMACAuthenticator
from finality_ref.errors import VerificationFailed
from finality_ref.models import SinkContext
from finality_ref.pop import Presenter, PresenterVerifierRegistry
from finality_ref.sink import FinalitySink
from finality_ref.state import InMemoryConsumptionStore
from .conftest import NOW, make_candidate, make_stack

PRESENTER_KEY = b"presenter-key-A"
PRESENTER = HMACAuthenticator(PRESENTER_KEY, key_id="presenter-A")


def strict_stack():
    c = make_candidate(authority_context={"model":"demo","session":"s-1","presenter_key_id":"presenter-A"})
    c, authn, evidence, state, authority, eff, _ = make_stack(c)
    sink = FinalitySink(
        context=SinkContext(c.sink_id,c.boundary_id,c.policy_epoch,frozenset(c.scope),c.effect_class),
        authenticator=authn,
        evidence_store=evidence,
        protected_state=state,
        consumption_store=InMemoryConsumptionStore(),
        effect_handle=eff.bind_for_sink(),
        clock=lambda: NOW,
        presenter_verifier=PresenterVerifierRegistry({"presenter-A": PRESENTER}),
        require_presentation_proof=True,
    )
    return c, authority, eff, sink


def make_proof(c, cap, *, signer=PRESENTER, now=NOW, **overrides):
    p = Presenter(signer).prove(
        capability_id=cap.capability_id,
        candidate_digest=c.digest(),
        sink_id=c.sink_id,
        boundary_id=c.boundary_id,
        nonce=c.nonce,
        presented_at_ns=now,
    )
    if not overrides:
        return p
    mutated = replace(p, **overrides, signature="")
    return replace(mutated, signature=signer.sign(mutated.unsigned()))


def test_strict_non_bearer_profile_accepts_valid_pop():
    c, authority, eff, sink = strict_stack()
    cap = authority.authorize(c)
    proof = make_proof(c, cap)
    assert sink.effectuate(c, cap, presentation_proof=proof).effect_status == "EFFECTIVE"
    assert len(eff.records) == 1


def test_stolen_capability_without_presenter_proof_is_insufficient():
    c, authority, eff, sink = strict_stack()
    cap = authority.authorize(c)
    with pytest.raises(VerificationFailed, match="presentation_proof_required"):
        sink.effectuate(c, cap)
    assert not eff.records


@pytest.mark.parametrize("field,value", [
    ("capability_id", "0"*64),
    ("candidate_digest", "1"*64),
    ("sink_id", "sink-B"),
    ("boundary_id", "boundary-B"),
    ("nonce", "other-nonce"),
    ("presenter_key_id", "presenter-B"),
])
def test_presentation_proof_binding_mutations_fail(field, value):
    c, authority, eff, sink = strict_stack()
    cap = authority.authorize(c)
    proof = make_proof(c, cap, **{field:value})
    with pytest.raises(VerificationFailed):
        sink.effectuate(c, cap, presentation_proof=proof)
    assert not eff.records


@pytest.mark.parametrize("offset", [2_000_000_001, 5_000_000_000, -2_000_000_001, -9_000_000_000])
def test_stale_or_future_presentation_proof_fails(offset):
    c, authority, eff, sink = strict_stack()
    cap = authority.authorize(c)
    proof = make_proof(c, cap, now=NOW+offset)
    with pytest.raises(VerificationFailed, match="presentation_stale"):
        sink.effectuate(c, cap, presentation_proof=proof)
    assert not eff.records


def test_wrong_presenter_secret_fails_even_with_same_key_id():
    c, authority, eff, sink = strict_stack()
    cap = authority.authorize(c)
    attacker = HMACAuthenticator(b"attacker-key", key_id="presenter-A")
    proof = make_proof(c, cap, signer=attacker)
    with pytest.raises(VerificationFailed, match="presentation_signature_invalid"):
        sink.effectuate(c, cap, presentation_proof=proof)
    assert not eff.records
