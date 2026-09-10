from __future__ import annotations

from dataclasses import replace
import pytest

from finality_ref.crypto import HMACAuthenticator
from finality_ref.effectors import NetworkEffector, StorageEffector
from finality_ref.errors import EffectDenied, ReplayDetected, VerificationFailed
from finality_ref.models import SinkContext
from finality_ref.sink import FinalitySink
from finality_ref.state import InMemoryConsumptionStore
from .conftest import NOW, make_candidate, make_stack, resign_cap


@pytest.mark.parametrize("sink_id,boundary_id", [
    ("sink-B", "boundary-A"),
    ("sink-A", "boundary-B"),
    ("sink-B", "boundary-B"),
    ("sink-shadow", "boundary-A"),
    ("sink-A", "boundary-shadow"),
])
def test_cross_sink_and_boundary_laundering_fails(sink_id, boundary_id):
    c, authn, evidence, state, authority, _, _ = make_stack()
    cap = authority.authorize(c)
    eff = NetworkEffector()
    sink2 = FinalitySink(
        context=SinkContext(
            sink_id=sink_id,
            boundary_id=boundary_id,
            policy_epoch=7,
            supported_scopes=frozenset({"POST:/payments"}),
            effect_class="network-egress",
        ),
        authenticator=authn,
        evidence_store=evidence,
        protected_state=state,
        consumption_store=InMemoryConsumptionStore(),
        effect_handle=eff.bind_for_sink(),
        clock=lambda: NOW,
    )
    with pytest.raises(VerificationFailed):
        sink2.effectuate(c, cap)
    assert not eff.records


@pytest.mark.parametrize("epoch", [0, 1, 6, 8, 9, 2**31-1])
def test_sink_policy_epoch_is_local_and_authoritative(epoch):
    c, authn, evidence, state, authority, _, _ = make_stack()
    cap = authority.authorize(c)
    eff = NetworkEffector()
    sink2 = FinalitySink(
        context=SinkContext("sink-A", "boundary-A", epoch, frozenset({"POST:/payments"}), "network-egress"),
        authenticator=authn,
        evidence_store=evidence,
        protected_state=state,
        consumption_store=InMemoryConsumptionStore(),
        effect_handle=eff.bind_for_sink(),
        clock=lambda: NOW,
    )
    with pytest.raises(VerificationFailed):
        sink2.effectuate(c, cap)


@pytest.mark.parametrize("supported", [
    frozenset(), frozenset({"SEND"}), frozenset({"DISPLAY"}),
    frozenset({"POST:/payments", "SEND"}),
])
def test_sink_local_scope_enforcement(supported):
    c, authn, evidence, state, authority, _, _ = make_stack()
    cap = authority.authorize(c)
    eff = NetworkEffector()
    sink2 = FinalitySink(
        context=SinkContext("sink-A", "boundary-A", 7, supported, "network-egress"),
        authenticator=authn, evidence_store=evidence, protected_state=state,
        consumption_store=InMemoryConsumptionStore(), effect_handle=eff.bind_for_sink(),
        clock=lambda: NOW,
    )
    if "POST:/payments" in supported:
        assert sink2.effectuate(c, cap).effect_status == "EFFECTIVE"
    else:
        with pytest.raises(VerificationFailed):
            sink2.effectuate(c, cap)


@pytest.mark.parametrize("now_offset", [1, 10, 1_000, 1_000_000, 4_999_999_999])
def test_capability_valid_within_window(now_offset):
    c, authn, evidence, state, authority, eff, _ = make_stack()
    cap = authority.authorize(c)
    sink = FinalitySink(
        context=SinkContext("sink-A", "boundary-A", 7, frozenset({"POST:/payments"}), "network-egress"),
        authenticator=authn, evidence_store=evidence, protected_state=state,
        consumption_store=InMemoryConsumptionStore(), effect_handle=eff.bind_for_sink(),
        clock=lambda: NOW + now_offset,
    )
    assert sink.effectuate(c, cap).effect_status == "EFFECTIVE"


@pytest.mark.parametrize("now_offset", [5_000_000_001, 6_000_000_000, 10_000_000_001, 60_000_000_000])
def test_expired_capability_fails_at_sink(now_offset):
    c, authn, evidence, state, authority, eff, _ = make_stack()
    cap = authority.authorize(c)
    sink = FinalitySink(
        context=SinkContext("sink-A", "boundary-A", 7, frozenset({"POST:/payments"}), "network-egress"),
        authenticator=authn, evidence_store=evidence, protected_state=state,
        consumption_store=InMemoryConsumptionStore(), effect_handle=eff.bind_for_sink(),
        clock=lambda: NOW + now_offset,
    )
    with pytest.raises(VerificationFailed):
        sink.effectuate(c, cap)


@pytest.mark.parametrize("new_destination", [
    "https://example.invalid/refunds", "https://evil.invalid/payments", "file:///tmp/x",
    "unix:///tmp/socket", "127.0.0.1:9000", "[::1]:9000", "https://example.invalid/payments?x=1",
    "https://example.invalid/payments#fragment",
])
def test_destination_substitution_after_authorization_fails(new_destination):
    c, _, _, _, authority, eff, sink = make_stack()
    cap = authority.authorize(c)
    with pytest.raises(VerificationFailed):
        sink.effectuate(replace(c, destination=new_destination), cap)
    assert not eff.records


@pytest.mark.parametrize("scope", [
    ("SEND",), ("DISPLAY",), ("WRITE:/records",), ("POST:/payments", "SEND"),
    ("POST:/payments", "POST:/payments"), tuple(),
])
def test_scope_expansion_or_change_after_authorization_fails(scope):
    c, _, _, _, authority, eff, sink = make_stack()
    cap = authority.authorize(c)
    with pytest.raises(VerificationFailed):
        sink.effectuate(replace(c, scope=scope), cap)
    assert not eff.records


@pytest.mark.parametrize("other_secret", [
    b"wrong-1", b"wrong-2", b"x"*32, b"\x00"*32, b"\xff"*32,
])
def test_sink_with_wrong_authority_key_rejects(other_secret):
    c, _, evidence, state, authority, _, _ = make_stack()
    cap = authority.authorize(c)
    bad_authn = HMACAuthenticator(other_secret)
    eff = NetworkEffector()
    sink = FinalitySink(
        context=SinkContext("sink-A", "boundary-A", 7, frozenset({"POST:/payments"}), "network-egress"),
        authenticator=bad_authn, evidence_store=evidence, protected_state=state,
        consumption_store=InMemoryConsumptionStore(), effect_handle=eff.bind_for_sink(), clock=lambda: NOW,
    )
    with pytest.raises(VerificationFailed):
        sink.effectuate(c, cap)
