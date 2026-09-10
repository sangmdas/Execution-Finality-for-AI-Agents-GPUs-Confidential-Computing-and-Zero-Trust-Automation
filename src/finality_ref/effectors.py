from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from .canonical import sha256_hex
from .errors import EffectDenied
from .models import CandidateAct


@dataclass(frozen=True)
class EffectRecord:
    channel: str
    candidate_digest: str
    effect_reference: str
    payload: Any


class _BoundHandle:
    __slots__ = ("_effector", "_marker")

    def __init__(self, effector: "GuardedEffector", marker: object):
        self._effector = effector
        self._marker = marker

    def commit(self, candidate: CandidateAct) -> EffectRecord:
        return self._effector._commit(candidate, self._marker)


class GuardedEffector:
    """Simulation of a consequence-bearing boundary.

    The public method refuses effect. A sink receives a non-serializable bound handle.
    This is a *reference seam*, not a claim of process-level isolation. Production
    deployments must put the effect path behind a privileged/physical boundary.
    """

    def __init__(self, channel: str):
        self.channel = channel
        self._marker = object()
        self._records: list[EffectRecord] = []
        self._lock = threading.Lock()
        self.fail_next = False

    def bind_for_sink(self) -> _BoundHandle:
        return _BoundHandle(self, self._marker)

    def direct_effect(self, candidate: CandidateAct) -> EffectRecord:
        raise EffectDenied(f"{self.channel}: direct effect path denied; Finality Sink required")

    def _commit(self, candidate: CandidateAct, marker: object) -> EffectRecord:
        if marker is not self._marker:
            raise EffectDenied(f"{self.channel}: invalid sink invocation")
        with self._lock:
            if self.fail_next:
                self.fail_next = False
                raise OSError(f"{self.channel}: injected downstream failure")
            ref = sha256_hex({
                "channel": self.channel,
                "candidate_digest": candidate.digest(),
                "ordinal": len(self._records),
            })
            rec = EffectRecord(self.channel, candidate.digest(), ref, candidate.payload)
            self._records.append(rec)
            return rec

    @property
    def records(self) -> tuple[EffectRecord, ...]:
        with self._lock:
            return tuple(self._records)


class NetworkEffector(GuardedEffector):
    def __init__(self): super().__init__("network-egress")


class StorageEffector(GuardedEffector):
    def __init__(self): super().__init__("storage-write")


class RendererEffector(GuardedEffector):
    def __init__(self): super().__init__("renderer")


class QueueEffector(GuardedEffector):
    def __init__(self): super().__init__("message-queue")


class ProcessEffector(GuardedEffector):
    def __init__(self): super().__init__("process-spawn")


class ActuatorEffector(GuardedEffector):
    def __init__(self): super().__init__("actuator")


class PaymentEffector(GuardedEffector):
    def __init__(self): super().__init__("payment-ledger")


class ModelOutputEffector(GuardedEffector):
    def __init__(self): super().__init__("model-output")


class DMAEffector(GuardedEffector):
    def __init__(self): super().__init__("dma-memory-release")


EFFECTOR_TYPES = {
    "network-egress": NetworkEffector,
    "storage-write": StorageEffector,
    "renderer": RendererEffector,
    "message-queue": QueueEffector,
    "process-spawn": ProcessEffector,
    "actuator": ActuatorEffector,
    "payment-ledger": PaymentEffector,
    "model-output": ModelOutputEffector,
    "dma-memory-release": DMAEffector,
}
