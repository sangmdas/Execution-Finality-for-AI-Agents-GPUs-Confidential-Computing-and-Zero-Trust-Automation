from __future__ import annotations

import time
from dataclasses import replace
from typing import Callable

from .canonical import sha256_hex
from .crypto import Authenticator
from .evidence import EvidenceStore
from .errors import ValidationDenied
from .models import Capability, CandidateAct, Decision, ValidationEvidence, build_hcad
from .policy import Policy
from .state import ProtectedState


Clock = Callable[[], int]


class ProtectedAuthority:
    def __init__(
        self,
        *,
        authority_id: str,
        policy: Policy,
        state: ProtectedState,
        evidence_store: EvidenceStore,
        authenticator: Authenticator,
        capability_ttl_ns: int = 5_000_000_000,
        clock: Clock = time.time_ns,
    ):
        self.authority_id = authority_id
        self.policy = policy
        self.state = state
        self.evidence_store = evidence_store
        self.authenticator = authenticator
        self.capability_ttl_ns = capability_ttl_ns
        self.clock = clock

    def authorize(self, candidate: CandidateAct, *, cost: int = 1, now_ns: int | None = None) -> Capability:
        now = self.clock() if now_ns is None else now_ns
        descriptor = build_hcad(candidate)
        allowed, reasons = self.policy.validate(candidate, now)
        if not allowed:
            raise ValidationDenied(",".join(reasons))

        # Protected state is advanced before capability availability. A later failure
        # burns availability rather than creating a replay window.
        transition = self.state.transition_for_authorization(candidate, cost=cost)

        evidence_core = {
            "authority_id": self.authority_id,
            "descriptor_digest": descriptor.digest(),
            "candidate_digest": candidate.digest(),
            "transition_id": transition.transition_id,
            "policy_epoch": candidate.policy_epoch,
            "decision": Decision.ALLOW.value,
            "reasons": [],
            "committed_at_ns": now,
            "key_id": self.authenticator.key_id,
        }
        evidence_id = sha256_hex(evidence_core)
        unsigned_evidence = {"evidence_id": evidence_id, **evidence_core}
        evidence = ValidationEvidence(
            evidence_id=evidence_id,
            authority_id=self.authority_id,
            descriptor_digest=descriptor.digest(),
            candidate_digest=candidate.digest(),
            transition_id=transition.transition_id,
            policy_epoch=candidate.policy_epoch,
            decision=Decision.ALLOW,
            reasons=(),
            committed_at_ns=now,
            key_id=self.authenticator.key_id,
            signature=self.authenticator.sign(unsigned_evidence),
        )
        self.evidence_store.commit(evidence)

        expires = min(candidate.issued_at_ns + candidate.freshness_ns, now + self.capability_ttl_ns)
        cap_core = {
            "authority_id": self.authority_id,
            "candidate_digest": candidate.digest(),
            "descriptor_digest": descriptor.digest(),
            "sink_id": candidate.sink_id,
            "boundary_id": candidate.boundary_id,
            "nonce": candidate.nonce,
            "scope": list(candidate.scope),
            "policy_epoch": candidate.policy_epoch,
            "evidence_id": evidence.evidence_id,
            "transition_id": transition.transition_id,
            "issued_at_ns": now,
            "expires_at_ns": expires,
            "key_id": self.authenticator.key_id,
        }
        capability_id = sha256_hex(cap_core)
        unsigned_cap = {"capability_id": capability_id, **cap_core}
        return Capability(
            capability_id=capability_id,
            authority_id=self.authority_id,
            candidate_digest=candidate.digest(),
            descriptor_digest=descriptor.digest(),
            sink_id=candidate.sink_id,
            boundary_id=candidate.boundary_id,
            nonce=candidate.nonce,
            scope=tuple(candidate.scope),
            policy_epoch=candidate.policy_epoch,
            evidence_id=evidence.evidence_id,
            transition_id=transition.transition_id,
            issued_at_ns=now,
            expires_at_ns=expires,
            key_id=self.authenticator.key_id,
            signature=self.authenticator.sign(unsigned_cap),
        )
