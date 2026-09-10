from __future__ import annotations

import pytest

from finality_ref.effectors import EFFECTOR_TYPES
from finality_ref.errors import EffectDenied, VerificationFailed
from .conftest import make_candidate, make_stack


CHANNEL_CASES = [
    ("network-egress", "SEND"),
    ("storage-write", "WRITE:/records"),
    ("renderer", "DISPLAY"),
    ("message-queue", "QUEUE:PUBLISH"),
    ("process-spawn", "SPAWN"),
    ("actuator", "ACTUATE"),
    ("payment-ledger", "SETTLE"),
    ("model-output", "PUBLISH"),
    ("dma-memory-release", "DMA:RELEASE"),
]

@pytest.mark.parametrize("channel,scope", CHANNEL_CASES)
def test_each_guarded_channel_allows_only_sink_mediated_effect(channel, scope):
    c = make_candidate(effect_class=channel, scope=(scope,))
    eff = EFFECTOR_TYPES[channel]()
    c, _, _, _, authority, eff, sink = make_stack(c, effector=eff)
    cap = authority.authorize(c)
    receipt = sink.effectuate(c, cap)
    assert receipt.effect_status == "EFFECTIVE"
    assert len(eff.records) == 1


@pytest.mark.parametrize("channel,scope", CHANNEL_CASES)
def test_each_guarded_channel_rejects_direct_bypass(channel, scope):
    c = make_candidate(effect_class=channel, scope=(scope,))
    eff = EFFECTOR_TYPES[channel]()
    with pytest.raises(EffectDenied):
        eff.direct_effect(c)
    assert len(eff.records) == 0


@pytest.mark.parametrize("channel,scope", CHANNEL_CASES)
def test_channel_substitution_after_authorization_fails(channel, scope):
    if channel == "network-egress":
        return
    c = make_candidate()
    _, _, _, _, authority, _, sink = make_stack(c)
    cap = authority.authorize(c)
    mutated = make_candidate(
        act_id=c.act_id,
        nonce=c.nonce,
        issued_at_ns=c.issued_at_ns,
        effect_class=channel,
        scope=(scope,),
        sink_id=c.sink_id,
        boundary_id=c.boundary_id,
    )
    with pytest.raises(VerificationFailed):
        sink.effectuate(mutated, cap)


@pytest.mark.parametrize("channel,scope", CHANNEL_CASES)
def test_wrong_effect_class_at_local_sink_fails(channel, scope):
    c = make_candidate(effect_class=channel, scope=(scope,))
    _, _, _, _, authority, _, sink = make_stack(c)
    cap = authority.authorize(c)
    # Sink is then asked to handle a candidate claiming another effect class.
    wrong = "storage-write" if channel != "storage-write" else "network-egress"
    from dataclasses import replace
    with pytest.raises(VerificationFailed):
        sink.effectuate(replace(c, effect_class=wrong), cap)
