from __future__ import annotations

from dataclasses import dataclass, field

from .models import ActStatus, CandidateAct


@dataclass(frozen=True)
class Policy:
    policy_epoch: int
    allowed_purposes: frozenset[str]
    allowed_jurisdictions: frozenset[str]
    allowed_sinks: frozenset[str]
    allowed_boundaries: frozenset[str]
    allowed_effect_classes: frozenset[str]
    allowed_scopes: frozenset[str]
    revoked_sources: frozenset[str] = field(default_factory=frozenset)
    required_runtime_evidence_digest: str | None = None
    max_future_skew_ns: int = 1_000_000_000

    def validate(self, candidate: CandidateAct, now_ns: int) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        if candidate.status != ActStatus.NON_EFFECTIVE:
            reasons.append("candidate_not_non_effective")
        if candidate.policy_epoch != self.policy_epoch:
            reasons.append("policy_epoch_mismatch")
        if candidate.purpose not in self.allowed_purposes:
            reasons.append("purpose_not_allowed")
        if candidate.jurisdiction not in self.allowed_jurisdictions:
            reasons.append("jurisdiction_not_allowed")
        if candidate.sink_id not in self.allowed_sinks:
            reasons.append("sink_not_allowed")
        if candidate.boundary_id not in self.allowed_boundaries:
            reasons.append("boundary_not_allowed")
        if candidate.effect_class not in self.allowed_effect_classes:
            reasons.append("effect_class_not_allowed")
        if not candidate.scope:
            reasons.append("empty_scope")
        if not set(candidate.scope).issubset(self.allowed_scopes):
            reasons.append("scope_not_allowed")
        if len(set(candidate.scope)) != len(candidate.scope):
            reasons.append("duplicate_scope")
        if candidate.source in self.revoked_sources:
            reasons.append("source_revoked")
        if candidate.freshness_ns <= 0:
            reasons.append("invalid_freshness")
        if now_ns < candidate.issued_at_ns - self.max_future_skew_ns:
            reasons.append("candidate_from_future")
        if now_ns > candidate.issued_at_ns + candidate.freshness_ns:
            reasons.append("candidate_stale")
        if self.required_runtime_evidence_digest is not None:
            if candidate.runtime_evidence_digest != self.required_runtime_evidence_digest:
                reasons.append("runtime_evidence_mismatch")
        return not reasons, tuple(reasons)
