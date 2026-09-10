from __future__ import annotations

from finality_ref.crypto import HMACAuthenticator
from finality_ref.models import SinkContext
from finality_ref.sink import FinalitySink
from finality_ref.state import InMemoryConsumptionStore
from .conftest import NOW, make_stack


def test_sink_receipt_can_use_key_separate_from_authority_key():
    c, authority_auth, evidence, state, authority, eff, _ = make_stack()
    receipt_auth = HMACAuthenticator(b"separate-sink-receipt-key", key_id="sink-receipt-key")
    sink = FinalitySink(
        context=SinkContext(c.sink_id,c.boundary_id,c.policy_epoch,frozenset(c.scope),c.effect_class),
        authenticator=authority_auth, receipt_authenticator=receipt_auth,
        evidence_store=evidence, protected_state=state, consumption_store=InMemoryConsumptionStore(),
        effect_handle=eff.bind_for_sink(), clock=lambda:NOW,
    )
    cap=authority.authorize(c)
    receipt=sink.effectuate(c,cap)
    assert receipt.key_id == "sink-receipt-key"
    assert receipt_auth.verify(receipt.unsigned(),receipt.signature,receipt.key_id)
    assert not authority_auth.verify(receipt.unsigned(),receipt.signature,receipt.key_id)


def test_receipt_key_cannot_verify_authority_capability():
    c, authority_auth, _, _, authority, _, _ = make_stack()
    receipt_auth = HMACAuthenticator(b"separate-sink-receipt-key", key_id="sink-receipt-key")
    cap=authority.authorize(c)
    assert authority_auth.verify(cap.unsigned(),cap.signature,cap.key_id)
    assert not receipt_auth.verify(cap.unsigned(),cap.signature,cap.key_id)
