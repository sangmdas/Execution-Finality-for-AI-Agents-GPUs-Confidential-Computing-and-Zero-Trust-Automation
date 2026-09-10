from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .crypto import Authenticator


@dataclass(frozen=True)
class PresentationProof:
    capability_id: str
    candidate_digest: str
    sink_id: str
    boundary_id: str
    nonce: str
    presented_at_ns: int
    presenter_key_id: str
    signature: str

    def unsigned(self) -> dict[str, object]:
        return {
            "capability_id": self.capability_id,
            "candidate_digest": self.candidate_digest,
            "sink_id": self.sink_id,
            "boundary_id": self.boundary_id,
            "nonce": self.nonce,
            "presented_at_ns": self.presented_at_ns,
            "presenter_key_id": self.presenter_key_id,
        }


class Presenter:
    def __init__(self, authenticator: Authenticator):
        self.authenticator = authenticator

    def prove(self, *, capability_id: str, candidate_digest: str, sink_id: str,
              boundary_id: str, nonce: str, presented_at_ns: int) -> PresentationProof:
        unsigned = {
            "capability_id": capability_id,
            "candidate_digest": candidate_digest,
            "sink_id": sink_id,
            "boundary_id": boundary_id,
            "nonce": nonce,
            "presented_at_ns": presented_at_ns,
            "presenter_key_id": self.authenticator.key_id,
        }
        return PresentationProof(signature=self.authenticator.sign(unsigned), **unsigned)


class PresenterVerifierRegistry:
    def __init__(self, verifiers: Mapping[str, Authenticator]):
        self.verifiers = dict(verifiers)

    def verify(self, proof: PresentationProof) -> bool:
        verifier = self.verifiers.get(proof.presenter_key_id)
        return bool(verifier and verifier.verify(proof.unsigned(), proof.signature, proof.presenter_key_id))
