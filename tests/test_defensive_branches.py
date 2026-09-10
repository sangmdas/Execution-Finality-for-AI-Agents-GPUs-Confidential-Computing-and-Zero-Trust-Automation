from __future__ import annotations

from dataclasses import replace
import threading

import pytest

from finality_ref.crypto import Ed25519Authenticator
from finality_ref.effectors import NetworkEffector
from finality_ref.errors import EffectDenied, EvidenceError, VerificationFailed
from finality_ref.sink import FinalitySink
from finality_ref.state import InMemoryConsumptionStore, ProtectedState
from finality_ref.surface import DeploymentManifest, EffectSurface
from tests.conftest import NOW, make_candidate, make_stack


def test_ed25519_verifier_only_instance_cannot_sign():
    signer = Ed25519Authenticator.generate("ed-defensive")
    verifier = signer.verifier()
    with pytest.raises(RuntimeError, match="verifier-only"):
        verifier.sign({"x": 1})


def test_guarded_effector_rejects_forged_bound_marker():
    candidate = make_candidate()
    effector = NetworkEffector()
    with pytest.raises(EffectDenied, match="invalid sink invocation"):
        effector._commit(candidate, object())  # adversarial direct call to the boundary seam


def test_evidence_store_rejects_duplicate_committed_evidence():
    candidate, _, evidence_store, _, authority, _, _ = make_stack()
    cap = authority.authorize(candidate)
    evidence = evidence_store.get(cap.evidence_id)
    assert evidence is not None
    with pytest.raises(EvidenceError, match="duplicate evidence id"):
        evidence_store.commit(evidence)


def test_evidence_store_verify_allow_missing_is_false():
    _, _, evidence_store, _, _, _, _ = make_stack()
    assert evidence_store.verify_allow("does-not-exist") is False


def test_sink_rejects_invalid_validation_evidence_signature():
    candidate, _, evidence_store, _, authority, _, sink = make_stack()
    cap = authority.authorize(candidate)
    evidence = evidence_store.get(cap.evidence_id)
    assert evidence is not None
    evidence_store.replace_for_adversarial_test(replace(evidence, signature="00" * 32))
    with pytest.raises(VerificationFailed, match="validation_evidence_signature_invalid"):
        sink.verify(candidate, cap, now_ns=NOW)


def test_sink_rejects_capability_when_local_protected_state_has_no_transition():
    candidate, authn, evidence_store, _, authority, effector, sink = make_stack()
    cap = authority.authorize(candidate)
    isolated_state = ProtectedState()
    isolated_sink = FinalitySink(
        context=sink.context,
        authenticator=authn,
        evidence_store=evidence_store,
        protected_state=isolated_state,
        consumption_store=InMemoryConsumptionStore(),
        effect_handle=effector.bind_for_sink(),
        clock=lambda: NOW,
    )
    with pytest.raises(VerificationFailed, match="protected_state_transition_invalid"):
        isolated_sink.verify(candidate, cap, now_ns=NOW)


@pytest.mark.parametrize("cost", [0, -1, -100])
def test_protected_state_rejects_nonpositive_cost(cost):
    state = ProtectedState()
    with pytest.raises(ValueError, match="cost must be positive"):
        state.transition_for_authorization(make_candidate(), cost=cost)


def test_protected_state_lock_and_missing_transition_accessors_are_explicit():
    state = ProtectedState()
    assert isinstance(state.lock, type(threading.RLock()))
    assert state.get_transition("missing") is None


def test_surface_audit_reports_duplicate_definition_without_calling_it_external_bypass():
    s = EffectSurface(
        name="internal-cache",
        channel="internal",
        externally_effective=False,
        sink_mediated=False,
        enforcement_boundary="none-required-for-non-effect",
        privileged=False,
    )
    findings = DeploymentManifest([s, s]).audit()
    assert any(f.reason == "duplicate_surface_definition" for f in findings)
    assert not any(f.reason == "unguarded_external_effect_path" for f in findings)


def test_evidence_store_rejects_invalid_signature_on_commit():
    candidate, authn, evidence_store, _, authority, _, _ = make_stack()
    cap = authority.authorize(candidate)
    evidence = evidence_store.get(cap.evidence_id)
    assert evidence is not None
    from finality_ref.evidence import EvidenceStore
    fresh_store = EvidenceStore(authn)
    with pytest.raises(EvidenceError, match="invalid evidence signature"):
        fresh_store.commit(replace(evidence, signature="00" * 32))


def test_ed25519_reports_missing_optional_crypto_dependency(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name.startswith("cryptography.hazmat.primitives.asymmetric.ed25519"):
            raise ImportError("injected missing cryptography")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    with pytest.raises(RuntimeError, match="install the 'crypto' extra"):
        Ed25519Authenticator(key_id="missing-dependency-test")
