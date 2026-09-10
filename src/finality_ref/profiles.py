from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SystemProfile:
    name: str
    sink_kind: str
    state_backend: str
    authenticator: str
    latency_target_us: int
    deployment_boundary: str
    notes: str


PROFILES = (
    SystemProfile("embedded-control", "actuator", "protected-memory", "device-key", 100, "MCU/secure-element", "hard real-time target; benchmark requires native implementation"),
    SystemProfile("accelerator-hot-path", "dma-memory-release", "device-memory", "device-key", 500, "GPU/DPU/SmartNIC", "descriptor precomputation and local verification"),
    SystemProfile("upf-egress", "network-egress", "local-durable", "HSM-key", 1000, "UPF/N6 or SmartNIC", "packet/flow consequence boundary"),
    SystemProfile("api-gateway", "network-egress", "sqlite/redis-like", "HSM-key", 2000, "reverse-proxy/gateway", "general API sidecar/gateway profile"),
    SystemProfile("storage-writer", "storage-write", "database", "KMS/HSM-key", 5000, "transactional writer", "bind to transaction/idempotency key"),
    SystemProfile("payment-finality", "payment-ledger", "durable-ledger", "HSM-key", 10000, "payment/ledger bridge", "prioritize non-replay and auditability"),
    SystemProfile("cross-region-governance", "network-egress", "replicated-durable", "HSM-key", 20000, "regional egress gateway", "network RTT may dominate"),
    SystemProfile("audit-heavy", "model-output", "append-only", "HSM-key", 50000, "output emitter", "full receipt retention and policy evidence"),
)
