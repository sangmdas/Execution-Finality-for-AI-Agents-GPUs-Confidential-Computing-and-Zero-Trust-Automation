# Threat Model — Red-Team View

## Security objective

The target invariant is narrow and testable:

> A consequence-bearing act must not become externally effective unless the exact Candidate Act is accepted by the protected authority, bound to committed evidence and protected state, presented to the intended Finality Sink, independently re-verified there, and consumed before/with external effectuation.

This is **not** a claim that the Python process is a TEE, that every operating system is unbypassable, or that the design eliminates all side/covert channels.

## Trust boundaries

1. **Untrusted/less-trusted compute plane** — AI model, agent, application, network function, payment logic, workflow engine.
2. **Protected authority plane** — policy, nonce/quota/budget/monotonic state, runtime evidence verification, authorization keys.
3. **Evidence plane** — signed validation evidence / LAVR storage.
4. **Finality Sink** — local effect boundary and independent verifier.
5. **External consequence channel** — network, storage, renderer, queue, process, actuator, ledger, model-output emitter, DMA/memory release, etc.
6. **Presenter** — optional proof-of-possession principal for strict non-bearer semantics.

## Attacker classes

- Malicious or compromised AI/model/workload.
- Compromised application process with ability to mutate arguments after policy evaluation.
- Network attacker replaying or redirecting artifacts.
- Insider with access to capability/evidence records but not protected keys.
- Concurrent attacker racing legitimate effectuation.
- Operator misconfiguration exposing a second effect path.
- Compromised sink host or sink key (stronger adversary; residual risk described below).

## Finality Sink attack analysis

### Direct bypass / alternate egress

**Attack:** ignore the sink and call a socket, file writer, queue, renderer, DMA engine or API client directly.

**Protocol result:** no software protocol can stop an effect path it does not mediate. The reference `GuardedEffector` demonstrates the intended interface, and `DeploymentManifest` flags known unguarded paths, but real prevention requires topology/privilege controls: kernel hooks, firewall/egress policy, service-mesh/gateway exclusivity, database permissions, device/IOMMU controls, SmartNIC/DPU mediation, secure display path, HSM/TEE boundary, or equivalent.

**Residual:** a hidden or newly introduced side path defeats the completeness assumption. This is the highest-priority deployment threat.

### Candidate mutation / TOCTOU

The sink recomputes both the whole-candidate digest and HCAD. Post-authorization changes to target, payload, scope, jurisdiction, purpose, effect class, nonce, epoch, runtime evidence or boundary fail.

### Sink substitution

Capabilities are sink- and boundary-bound. The sink rebuilds its descriptor with *local* identity. A capability issued for Sink A cannot simply be accepted at Sink B.

### Replay and duplicate effect

Consumption uses an atomic claim. The in-memory implementation is locked; the SQLite implementation uses a primary-key uniqueness constraint inside `BEGIN IMMEDIATE`. Concurrency tests race up to 64 contenders and require exactly one effect.

### Crash after consume, before effect

The reference deliberately chooses **at-most-once safety**: capability consumption is retained if the downstream effect fails. This avoids replay but can lose availability. Exactly-once effect across independent systems cannot be guaranteed by this library alone; use a transactional outbox, idempotent downstream transaction ID, or effect-specific atomic primitive.

### Stolen capability

Act/sink/boundary/state/evidence binding severely limits reuse, but a stolen exact capability and exact act can still be raced in the basic profile. The **strict non-bearer profile** therefore requires a fresh proof-of-possession signed by a presenter key bound into the Candidate Act.

### Evidence substitution

Evidence is signed and bound by evidence ID, candidate digest, descriptor digest, transition ID and epoch. Signed-but-inconsistent evidence is still rejected by the sink.

### Protected-state rollback

The in-memory store cannot itself resist host rollback. Production state must be rollback-resistant (TPM monotonic state, HSM/TEE sealed state with anti-rollback, protected database/ledger or equivalent). The protocol makes the state reference explicit; it does not magically harden an untrusted storage medium.

### Policy epoch rollback / split brain

The sink has a local expected epoch and rejects capability/evidence from another epoch. Distributed policy deployment still needs safe epoch coordination. A partition can create denial of service; permitting fail-open is prohibited by the model.

### Sink compromise

If an attacker fully controls the actual privileged Finality Sink *and* the physical/OS effect boundary, the attacker may bypass verification. This is outside what a software protocol can cryptographically repair. Mitigations are isolation, measured boot/attestation, minimal sink TCB, code signing, privilege separation, hardware roots, independent monitoring and key isolation.

### Key compromise

Authority-key compromise can mint capabilities/evidence. Sink-receipt keys should be separate from authority keys. Presenter PoP keys should also be separate. HSM/TEE-backed asymmetric keys are recommended in multi-party deployments.

### Canonicalization ambiguity

The reference rejects floating point values in security-bound material, requires string map keys, normalizes Unicode values/keys to NFC, rejects collisions after normalization, uses explicit scalar/UTF-8 key ordering and deterministic UTF-8 JSON. Python, Node and Go execute positive and rejection conformance vectors, including decomposed Unicode. The runtimes do not all ship the same Unicode-data release, so the cross-language claim is tied to the included test repertoire rather than an exhaustive proof for every future code point. The interop profile is intentionally narrower than arbitrary JSON; see `CANONICALIZATION_PROFILE.md`.

### Resource exhaustion / DoS

Fail-closed finality can be attacked to reduce availability. Rate limits, bounded descriptor size, queue admission, resource reservations and overload behavior are deployment concerns. Security failure must not become a fail-open effect path.

### Side/covert channels

Timing, cache, RF, power and other covert/side channels are not solved by act finality. Likewise, logging/telemetry becomes an external effect if it can disclose protected content and must be modeled as a channel when relevant.

## Comparison with adjacent controls

This architecture is not credible if described as universally “better than existing security.” It addresses a different invariant and composes with existing mechanisms:

- **OAuth/RAR/DPoP/capability systems** can express granular authorization and proof-of-possession. They can supply inputs or even implement parts of the capability layer. The finality-specific requirement is that the exact effect is rechecked at the actual effect boundary and single-use state is enforced there.
- **RATS/remote attestation** proves properties about an environment; it does not, by itself, authorize every subsequent consequence-bearing act. Runtime attestation evidence is an input to the authority/sink.
- **TEE/HSM/secure enclaves** protect code/keys/state but do not automatically ensure every external effect crosses a particular verified boundary. They are excellent places to host authority or sink components.
- **Sandboxing** restricts what code can do; a permitted network/file/device path may still carry an unauthorized exact action. Finality can sit at those permitted exits.
- **OPA/policy engines** decide policy. Finality focuses on enforcing the decision against the exact act at consequence time.
- **Database transactions/idempotency keys** are stronger than this generic reference for their specific atomicity domain and should be used by a storage/payment sink where available.
- **Audit logs/SCITT-like transparency** provide evidence but do not necessarily block an act before effect. LAVR-like evidence is load-bearing only when the sink requires it.
- **ZK/HE/confidential computing** protect computation/data properties; they do not inherently decide whether a concrete external effect is authorized.

The defensible claim is therefore **composition plus a specific finality invariant**, not replacement of all existing controls.
