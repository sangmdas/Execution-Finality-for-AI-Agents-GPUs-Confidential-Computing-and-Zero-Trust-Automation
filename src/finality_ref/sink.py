from __future__ import annotations

import time
from typing import Callable, Protocol

from .canonical import sha256_hex
from .crypto import Authenticator
from .evidence import EvidenceStore
from .errors import EffectDenied, VerificationFailed
from .models import ActStatus, Capability, CandidateAct, Decision, SinkContext, SinkReceipt, build_hcad
from .pop import PresentationProof, PresenterVerifierRegistry
from .state import ProtectedState


class ConsumptionStore(Protocol):
    def claim(self, capability_id: str, *, sink_id: str, boundary_id: str, nonce: str, now_ns: int) -> None: ...


class EffectHandle(Protocol):
    def commit(self, candidate: CandidateAct): ...


Clock = Callable[[], int]


class FinalitySink:
    def __init__(
        self,
        *,
        context: SinkContext,
        authenticator: Authenticator,
        evidence_store: EvidenceStore,
        protected_state: ProtectedState,
        consumption_store: ConsumptionStore,
        effect_handle: EffectHandle,
        clock: Clock = time.time_ns,
        max_clock_skew_ns: int = 1_000_000_000,
        receipt_authenticator: Authenticator | None = None,
        presenter_verifier: PresenterVerifierRegistry | None = None,
        require_presentation_proof: bool = False,
        presentation_freshness_ns: int = 2_000_000_000,
    ):
        self.context = context
        self.authenticator = authenticator
        self.evidence_store = evidence_store
        self.protected_state = protected_state
        self.consumption_store = consumption_store
        self.effect_handle = effect_handle
        self.clock = clock
        self.max_clock_skew_ns = max_clock_skew_ns
        self.receipt_authenticator = receipt_authenticator or authenticator
        self.presenter_verifier = presenter_verifier
        self.require_presentation_proof = require_presentation_proof
        self.presentation_freshness_ns = presentation_freshness_ns

    def _fail(self, message: str) -> None:
        raise VerificationFailed(message)

    def verify(self, candidate: CandidateAct, cap: Capability, *, now_ns: int | None = None, presentation_proof: PresentationProof | None = None) -> str:
        now = self.clock() if now_ns is None else now_ns
        if candidate.status != ActStatus.NON_EFFECTIVE:
            self._fail("candidate_not_non_effective")
        if candidate.effect_class != self.context.effect_class:
            self._fail("effect_class_mismatch")
        if candidate.sink_id != self.context.sink_id or cap.sink_id != self.context.sink_id:
            self._fail("sink_binding_mismatch")
        if candidate.boundary_id != self.context.boundary_id or cap.boundary_id != self.context.boundary_id:
            self._fail("boundary_binding_mismatch")
        if candidate.policy_epoch != self.context.policy_epoch or cap.policy_epoch != self.context.policy_epoch:
            self._fail("policy_epoch_mismatch")
        if tuple(candidate.scope) != tuple(cap.scope):
            self._fail("scope_binding_mismatch")
        if not set(cap.scope).issubset(self.context.supported_scopes):
            self._fail("scope_not_supported_by_sink")
        if cap.nonce != candidate.nonce:
            self._fail("nonce_binding_mismatch")
        if now < cap.issued_at_ns - self.max_clock_skew_ns:
            self._fail("capability_from_future")
        if now > cap.expires_at_ns:
            self._fail("capability_expired")
        if cap.expires_at_ns > candidate.issued_at_ns + candidate.freshness_ns:
            self._fail("capability_outlives_candidate")
        if not self.authenticator.verify(cap.unsigned(), cap.signature, cap.key_id):
            self._fail("capability_signature_invalid")
        if self.require_presentation_proof:
            if presentation_proof is None or self.presenter_verifier is None:
                self._fail("presentation_proof_required")
            expected_key = candidate.authority_context.get("presenter_key_id")
            if not isinstance(expected_key, str) or presentation_proof.presenter_key_id != expected_key:
                self._fail("presenter_binding_mismatch")
            if presentation_proof.capability_id != cap.capability_id:
                self._fail("presentation_capability_mismatch")
            if presentation_proof.candidate_digest != candidate.digest():
                self._fail("presentation_candidate_mismatch")
            if presentation_proof.sink_id != self.context.sink_id or presentation_proof.boundary_id != self.context.boundary_id:
                self._fail("presentation_sink_boundary_mismatch")
            if presentation_proof.nonce != candidate.nonce:
                self._fail("presentation_nonce_mismatch")
            if abs(now - presentation_proof.presented_at_ns) > self.presentation_freshness_ns:
                self._fail("presentation_stale")
            if not self.presenter_verifier.verify(presentation_proof):
                self._fail("presentation_signature_invalid")
        if cap.candidate_digest != candidate.digest():
            self._fail("candidate_digest_mismatch")

        # Sink-side descriptor is rebuilt using local sink and boundary identity.
        local_descriptor = build_hcad(
            candidate,
            sink_id=self.context.sink_id,
            boundary_id=self.context.boundary_id,
        )
        if cap.descriptor_digest != local_descriptor.digest():
            self._fail("descriptor_digest_mismatch")

        evidence = self.evidence_store.get(cap.evidence_id)
        if evidence is None:
            self._fail("validation_evidence_missing")
        if not self.authenticator.verify(evidence.unsigned(), evidence.signature, evidence.key_id):
            self._fail("validation_evidence_signature_invalid")
        if evidence.decision != Decision.ALLOW:
            self._fail("validation_evidence_not_allow")
        if evidence.authority_id != cap.authority_id:
            self._fail("authority_binding_mismatch")
        if evidence.candidate_digest != cap.candidate_digest:
            self._fail("evidence_candidate_mismatch")
        if evidence.descriptor_digest != cap.descriptor_digest:
            self._fail("evidence_descriptor_mismatch")
        if evidence.transition_id != cap.transition_id:
            self._fail("evidence_transition_mismatch")
        if evidence.policy_epoch != cap.policy_epoch:
            self._fail("evidence_epoch_mismatch")
        if not self.protected_state.verify_transition(cap.transition_id, candidate):
            self._fail("protected_state_transition_invalid")
        return local_descriptor.digest()

    def effectuate(self, candidate: CandidateAct, cap: Capability, *, now_ns: int | None = None, presentation_proof: PresentationProof | None = None) -> SinkReceipt:
        now = self.clock() if now_ns is None else now_ns
        descriptor_digest = self.verify(candidate, cap, now_ns=now, presentation_proof=presentation_proof)

        # Claim/burn before effect. If downstream effect fails, the capability stays
        # consumed. This chooses at-most-once safety over automatic retry.
        self.consumption_store.claim(
            cap.capability_id,
            sink_id=self.context.sink_id,
            boundary_id=self.context.boundary_id,
            nonce=cap.nonce,
            now_ns=now,
        )

        effect_status = "EFFECTIVE"
        effect_reference: str | None = None
        try:
            record = self.effect_handle.commit(candidate)
            effect_reference = record.effect_reference
        except Exception as exc:
            effect_status = "EFFECT_FAILED_AFTER_CONSUMPTION"
            # No retry with the same capability is permitted.
            raise EffectDenied(str(exc)) from exc

        receipt_core = {
            "capability_id": cap.capability_id,
            "candidate_digest": candidate.digest(),
            "descriptor_digest": descriptor_digest,
            "sink_id": self.context.sink_id,
            "boundary_id": self.context.boundary_id,
            "transition_id": cap.transition_id,
            "scope": list(cap.scope),
            "effect_status": effect_status,
            "committed_at_ns": now,
            "effect_reference": effect_reference,
            "key_id": self.receipt_authenticator.key_id,
        }
        receipt_id = sha256_hex(receipt_core)
        unsigned = {"receipt_id": receipt_id, **receipt_core}
        return SinkReceipt(
            receipt_id=receipt_id,
            capability_id=cap.capability_id,
            candidate_digest=candidate.digest(),
            descriptor_digest=descriptor_digest,
            sink_id=self.context.sink_id,
            boundary_id=self.context.boundary_id,
            transition_id=cap.transition_id,
            scope=tuple(cap.scope),
            effect_status=effect_status,
            committed_at_ns=now,
            effect_reference=effect_reference,
            key_id=self.receipt_authenticator.key_id,
            signature=self.receipt_authenticator.sign(unsigned),
        )
