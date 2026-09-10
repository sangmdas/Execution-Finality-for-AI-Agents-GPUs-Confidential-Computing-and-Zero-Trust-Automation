from __future__ import annotations

from dataclasses import replace
import itertools
import pytest

from finality_ref.authority import ProtectedAuthority
from finality_ref.crypto import HMACAuthenticator
from finality_ref.effectors import EFFECTOR_TYPES, NetworkEffector
from finality_ref.evidence import EvidenceStore
from finality_ref.models import CandidateAct, SinkContext
from finality_ref.policy import Policy
from finality_ref.sink import FinalitySink
from finality_ref.state import InMemoryConsumptionStore, ProtectedState

NOW = 1_800_000_000_000_000_000
SECRET = b"finality-reference-test-key-32bytes!!"
_counter = itertools.count()


def make_candidate(**overrides):
    idx = next(_counter)
    base = dict(
        act_id=f"act-{idx}",
        act_class="api-call",
        effect_class="network-egress",
        source="agent-A",
        destination="https://example.invalid/payments",
        purpose="approved-purpose",
        jurisdiction="EU",
        policy_epoch=7,
        nonce=f"nonce-{idx}",
        issued_at_ns=NOW - 10_000,
        freshness_ns=10_000_000_000,
        sink_id="sink-A",
        boundary_id="boundary-A",
        scope=("POST:/payments",),
        payload={"amount_minor": 1000, "currency": "EUR", "beneficiary": "B1"},
        runtime_evidence_digest="runtime-ok",
        authority_context={"model": "demo", "session": "s-1"},
    )
    base.update(overrides)
    return CandidateAct(**base)


def make_policy(**overrides):
    base = dict(
        policy_epoch=7,
        allowed_purposes=frozenset({"approved-purpose", "diagnostic", "render"}),
        allowed_jurisdictions=frozenset({"EU", "US", "IN"}),
        allowed_sinks=frozenset({"sink-A", "sink-B"}),
        allowed_boundaries=frozenset({"boundary-A", "boundary-B"}),
        allowed_effect_classes=frozenset(EFFECTOR_TYPES.keys()),
        allowed_scopes=frozenset({
            "POST:/payments", "WRITE:/records", "DISPLAY", "PUBLISH", "SEND",
            "SPAWN", "ACTUATE", "SETTLE", "DMA:RELEASE", "QUEUE:PUBLISH"
        }),
        revoked_sources=frozenset(),
        required_runtime_evidence_digest="runtime-ok",
    )
    base.update(overrides)
    return Policy(**base)


def make_stack(candidate=None, *, effector=None, policy=None, state=None, consumption=None, secret=SECRET):
    candidate = candidate or make_candidate()
    authn = HMACAuthenticator(secret)
    evidence = EvidenceStore(authn)
    state = state or ProtectedState()
    policy = policy or make_policy()
    authority = ProtectedAuthority(
        authority_id="authority-A",
        policy=policy,
        state=state,
        evidence_store=evidence,
        authenticator=authn,
        capability_ttl_ns=5_000_000_000,
        clock=lambda: NOW,
    )
    effector = effector or (EFFECTOR_TYPES[candidate.effect_class]() if candidate.effect_class in EFFECTOR_TYPES else NetworkEffector())
    context = SinkContext(
        sink_id=candidate.sink_id,
        boundary_id=candidate.boundary_id,
        policy_epoch=candidate.policy_epoch,
        supported_scopes=frozenset(candidate.scope),
        effect_class=candidate.effect_class,
    )
    sink = FinalitySink(
        context=context,
        authenticator=authn,
        evidence_store=evidence,
        protected_state=state,
        consumption_store=consumption or InMemoryConsumptionStore(),
        effect_handle=effector.bind_for_sink(),
        clock=lambda: NOW,
    )
    return candidate, authn, evidence, state, authority, effector, sink


def resign_cap(cap, authn, **changes):
    mutated = replace(cap, **changes, signature="")
    return replace(mutated, signature=authn.sign(mutated.unsigned()))


def resign_evidence(evidence, authn, **changes):
    mutated = replace(evidence, **changes, signature="")
    return replace(mutated, signature=authn.sign(mutated.unsigned()))


@pytest.fixture
def stack():
    return make_stack()
