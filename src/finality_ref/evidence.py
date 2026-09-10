from __future__ import annotations

import threading

from .crypto import Authenticator
from .errors import EvidenceError
from .models import Decision, ValidationEvidence


class EvidenceStore:
    def __init__(self, authenticator: Authenticator):
        self.authenticator = authenticator
        self._records: dict[str, ValidationEvidence] = {}
        self._lock = threading.RLock()
        self.fail_commits = False

    def commit(self, evidence: ValidationEvidence) -> None:
        if self.fail_commits:
            raise EvidenceError("evidence commit failure injected")
        if not self.authenticator.verify(evidence.unsigned(), evidence.signature, evidence.key_id):
            raise EvidenceError("invalid evidence signature")
        with self._lock:
            if evidence.evidence_id in self._records:
                raise EvidenceError("duplicate evidence id")
            self._records[evidence.evidence_id] = evidence

    def get(self, evidence_id: str) -> ValidationEvidence | None:
        with self._lock:
            return self._records.get(evidence_id)

    def verify_allow(self, evidence_id: str) -> bool:
        evidence = self.get(evidence_id)
        return bool(
            evidence
            and evidence.decision == Decision.ALLOW
            and self.authenticator.verify(evidence.unsigned(), evidence.signature, evidence.key_id)
        )

    def replace_for_adversarial_test(self, evidence: ValidationEvidence) -> None:
        with self._lock:
            self._records[evidence.evidence_id] = evidence
