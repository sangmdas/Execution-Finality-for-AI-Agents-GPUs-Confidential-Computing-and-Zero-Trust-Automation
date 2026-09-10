from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from .canonical import sha256_hex


class ActStatus(str, Enum):
    NON_EFFECTIVE = "NON_EFFECTIVE"
    EFFECTIVE = "EFFECTIVE"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True)
class CandidateAct:
    act_id: str
    act_class: str
    effect_class: str
    source: str
    destination: str
    purpose: str
    jurisdiction: str
    policy_epoch: int
    nonce: str
    issued_at_ns: int
    freshness_ns: int
    sink_id: str
    boundary_id: str
    scope: tuple[str, ...]
    payload: Any
    runtime_evidence_digest: str
    authority_context: Mapping[str, Any] = field(default_factory=dict)
    status: ActStatus = ActStatus.NON_EFFECTIVE

    def payload_digest(self) -> str:
        return sha256_hex(self.payload)

    def digest(self) -> str:
        return sha256_hex(self)


@dataclass(frozen=True)
class HCAD:
    schema: str
    act_id: str
    act_class: str
    effect_class: str
    source: str
    destination: str
    purpose: str
    jurisdiction: str
    policy_epoch: int
    nonce: str
    issued_at_ns: int
    freshness_ns: int
    sink_id: str
    boundary_id: str
    scope: tuple[str, ...]
    payload_digest: str
    runtime_evidence_digest: str

    def digest(self) -> str:
        return sha256_hex(self)


@dataclass(frozen=True)
class StateTransition:
    transition_id: str
    nonce: str
    source: str
    before_version: int
    after_version: int
    quota_before: int
    quota_after: int
    budget_before: int
    budget_after: int
    policy_epoch: int


@dataclass(frozen=True)
class ValidationEvidence:
    evidence_id: str
    authority_id: str
    descriptor_digest: str
    candidate_digest: str
    transition_id: str
    policy_epoch: int
    decision: Decision
    reasons: tuple[str, ...]
    committed_at_ns: int
    signature: str
    key_id: str

    def unsigned(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "authority_id": self.authority_id,
            "descriptor_digest": self.descriptor_digest,
            "candidate_digest": self.candidate_digest,
            "transition_id": self.transition_id,
            "policy_epoch": self.policy_epoch,
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "committed_at_ns": self.committed_at_ns,
            "key_id": self.key_id,
        }


@dataclass(frozen=True)
class Capability:
    capability_id: str
    authority_id: str
    candidate_digest: str
    descriptor_digest: str
    sink_id: str
    boundary_id: str
    nonce: str
    scope: tuple[str, ...]
    policy_epoch: int
    evidence_id: str
    transition_id: str
    issued_at_ns: int
    expires_at_ns: int
    key_id: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "authority_id": self.authority_id,
            "candidate_digest": self.candidate_digest,
            "descriptor_digest": self.descriptor_digest,
            "sink_id": self.sink_id,
            "boundary_id": self.boundary_id,
            "nonce": self.nonce,
            "scope": list(self.scope),
            "policy_epoch": self.policy_epoch,
            "evidence_id": self.evidence_id,
            "transition_id": self.transition_id,
            "issued_at_ns": self.issued_at_ns,
            "expires_at_ns": self.expires_at_ns,
            "key_id": self.key_id,
        }


@dataclass(frozen=True)
class SinkContext:
    sink_id: str
    boundary_id: str
    policy_epoch: int
    supported_scopes: frozenset[str]
    effect_class: str


@dataclass(frozen=True)
class SinkReceipt:
    receipt_id: str
    capability_id: str
    candidate_digest: str
    descriptor_digest: str
    sink_id: str
    boundary_id: str
    transition_id: str
    scope: tuple[str, ...]
    effect_status: str
    committed_at_ns: int
    effect_reference: str | None
    signature: str
    key_id: str

    def unsigned(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "capability_id": self.capability_id,
            "candidate_digest": self.candidate_digest,
            "descriptor_digest": self.descriptor_digest,
            "sink_id": self.sink_id,
            "boundary_id": self.boundary_id,
            "transition_id": self.transition_id,
            "scope": list(self.scope),
            "effect_status": self.effect_status,
            "committed_at_ns": self.committed_at_ns,
            "effect_reference": self.effect_reference,
            "key_id": self.key_id,
        }


def build_hcad(candidate: CandidateAct, *, sink_id: str | None = None, boundary_id: str | None = None) -> HCAD:
    """Build the machine-verifiable act descriptor.

    sink_id/boundary_id may be supplied by a Finality Sink so the sink binds
    verification to its own local identity rather than trusting candidate input.
    """
    return HCAD(
        schema="finality-hcad/v1",
        act_id=candidate.act_id,
        act_class=candidate.act_class,
        effect_class=candidate.effect_class,
        source=candidate.source,
        destination=candidate.destination,
        purpose=candidate.purpose,
        jurisdiction=candidate.jurisdiction,
        policy_epoch=candidate.policy_epoch,
        nonce=candidate.nonce,
        issued_at_ns=candidate.issued_at_ns,
        freshness_ns=candidate.freshness_ns,
        sink_id=sink_id if sink_id is not None else candidate.sink_id,
        boundary_id=boundary_id if boundary_id is not None else candidate.boundary_id,
        scope=tuple(candidate.scope),
        payload_digest=candidate.payload_digest(),
        runtime_evidence_digest=candidate.runtime_evidence_digest,
    )
