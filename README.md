# Execution-Finality Foundational Architecture — Runnable Reference Implementation

A runnable, adversarially tested reference implementation of an **execution-finality architecture** in which a consequence-bearing operation is first represented as a **Candidate Act in a non-effective state**, validated inside a protected authority domain, bound to protected validation evidence and state, and permitted to become externally effective only after an **independently verifying Finality Sink** accepts the exact act and atomically/safely consumes its authority.

This repository is intentionally more than a conceptual diagram. It contains executable Python code, Go and Node.js interoperability verifiers, deterministic cryptographic vectors, 481 collected automated tests, replay/concurrency tests, fault injection, system/latency profiles, a wide-channel deployment audit, a strict proof-of-possession profile, benchmark tooling, threat models and red-team findings.

## 1. What this implementation is trying to prove

It demonstrates the following engineering proposition:

> **Computation may prepare an action, but preparation is not authority to cause an external consequence.**

The implementation separates:

**Compute plane** → generates a Candidate Act.

**Non-effective hold state** → Candidate Act may be serialized, buffered, ranked, encrypted or otherwise prepared, but it has no effect path.

**Protected authority / PED** → validates policy and runtime predicates and advances protected state.

**Protected validation evidence / LAVR** → is committed before a capability becomes available.

**Scoped capability** → binds the exact Candidate Act, descriptor, sink, boundary, nonce, scope, policy epoch, evidence and state transition.

**Finality Sink** → independently reconstructs the local descriptor and checks all load-bearing bindings.

**Consumption** → single-use authority is claimed/burned before external effect in the generic reference.

**External effect** → only then does the guarded consequence channel execute.

## 2. Mapping to the foundational FIG. 1A–1C chain

The implementation follows the supplied architecture step-for-step:

`100 Compute/Workload Plane`
→ `102 Candidate Act Generated`
→ `104 Non-Effective Staging/Hold State`
→ `106 Protected Authority/PED`
→ `108 HCAD / Machine-Verifiable Act Descriptor`
→ `110 Protected Predicate Validation`
→ `118 Protected State Update`
→ `120 Protected Validation Evidence/LAVR Commitment`
→ `122 Scoped Non-Bearer Capability`
→ `124 Finality Sink`
→ `126 Sink-Side Descriptor Build/Measurement`
→ `128 Finality Sink Verification`
→ `130 Capability Consumption`
→ `137 Sink-Side Finality Receipt`
→ `138 Externally Effective Act`

Failure branches remain non-effective and never invoke the guarded effector.

See `docs/ARCHITECTURE.md` for the exact code mapping.

## 3. Repository layout

```text
src/finality_ref/
  authority.py        protected validation + evidence-before-capability ordering
  canonical.py        narrow deterministic canonical representation
  crypto.py           HMAC reference + optional Ed25519 authenticator
  effectors.py        guarded consequence-channel simulations
  evidence.py         signed validation evidence store
  models.py           Candidate Act / HCAD / capability / receipts
  policy.py           policy and freshness predicates
  pop.py              strict non-bearer proof-of-possession profile
  profiles.py         system and latency profiles
  sink.py             independent Finality Sink verification + effectuation
  state.py            protected state + in-memory/SQLite single-use stores
  surface.py          wide-channel deployment coverage audit

tests/                481 adversarial collected cases
vectors/              deterministic Python/Go/Node interoperability vectors
go/                    Go canonicalization/hash/HMAC verifier
node/                  Node.js canonicalization/hash/HMAC verifier
examples/              runnable normal and strict-non-bearer flows
configs/               deployment/latency profiles
benchmarks/            measured reference results
docs/                  architecture, threat model, deployment, limits, red team
```

## 4. Run it

Python 3.11+ is sufficient for the core dependency-free HMAC reference.

```bash
python -m pip install -e '.[dev,crypto]'
pytest -q
python examples/demo.py
python examples/strict_non_bearer.py
node node/verify.mjs vectors/interop.json
(cd go && go run -mod=vendor . ../vectors/interop.json)
```

Or:

```bash
./scripts/run_all.sh
```

## 5. What the test suite attacks

The suite does not only test the happy path. It actively attempts to violate the finality invariant through:

- Candidate Act substitution after authorization.
- Payload, target, purpose, jurisdiction, runtime evidence and scope mutation.
- Re-signed but structurally inconsistent capabilities.
- Re-signed but semantically inconsistent evidence.
- Sink substitution, shadow sink and boundary substitution.
- Policy-epoch mismatch and downgrade.
- Stale/future capability presentation.
- Missing/failed evidence persistence.
- Protected-state transition mismatch.
- Sequential replay and parallel replay races.
- SQLite durable claim races with multiple concurrent contenders.
- Effect failure after capability consumption.
- Direct network, storage, renderer, queue, process, actuator, payment, model-output and DMA effect attempts.
- Twenty-class wide-channel deployment surface checks.
- Unicode/canonicalization/key-collision/float ambiguity cases.
- Seeded payload and destination mutation fuzz cases.
- Capability theft in strict proof-of-possession mode.
- Cross-language Python/Node/Go canonicalization + SHA-256 + HMAC vectors.

Run:

```bash
pytest --collect-only -q
```

to see the exact current count rather than relying on a README number.

## 6. Why the Finality Sink exists if validation already passed

A policy decision at time **T1** does not prove that the exact bytes/arguments/target crossing an external boundary at **T2** are unchanged. Between T1 and T2 there may be application mutation, confused-deputy behavior, stale policy, redirect/substitution, replay, cross-sink use or an alternate consequence channel.

The sink is therefore not merely another policy engine. It is the final enforcement point that:

1. identifies its local sink and boundary;
2. reconstructs/measures the act descriptor locally;
3. verifies exact Candidate Act and descriptor digests;
4. verifies sink, boundary, scope, nonce and policy epoch;
5. verifies committed validation evidence;
6. verifies protected-state transition;
7. optionally verifies fresh presenter proof-of-possession;
8. consumes single-use authority;
9. invokes the consequence channel;
10. produces sink-side finality evidence.

## 7. “Non-bearer” — strict interpretation

A serious red-team review exposed an important distinction.

A capability can be extraordinarily narrow—act-bound, sink-bound, boundary-bound, nonce-bound and single-use—and still be usable by a thief who steals the **exact capability plus exact Candidate Act** before legitimate use. Under a strong definition, that is not yet strictly non-bearer.

Therefore this repository implements a **strict proof-of-possession profile**. The Candidate Act binds a presenter key identity, and the sink requires a fresh signature over:

`capability_id + candidate_digest + sink + boundary + nonce + presentation time`

Possession of the serialized capability alone is then insufficient.

The HMAC presenter is a runnable demonstration. In multi-party production environments use a protected asymmetric workload/device/enclave key, mTLS/channel binding, DPoP-like key proof or equivalent mechanism.

## 8. Wide-channel attack model

A Finality Sink is meaningless if the workload can bypass it through another path.

The repository therefore models a large effect surface: network egress, storage, renderer, queue, process spawn, actuator, payment/ledger, model output and DMA/memory release. The deployment audit treats any externally effective declared surface that is not sink-mediated as **CRITICAL**.

This still does not prove there is no hidden path. Real non-bypassability comes from deployment controls such as:

- kernel/LSM/eBPF or OS privilege separation;
- firewall/egress policy and routing ownership;
- exclusive database/service credentials;
- service-mesh or reverse-proxy enforcement;
- IOMMU/driver/device mediation;
- SmartNIC/DPU enforcement;
- TEE/HSM/secure-element controller;
- protected display/actuator path;
- payment/ledger transaction boundary.

That limitation is explicit because claiming that ordinary Python code alone creates a physical non-bypassable boundary would undermine the credibility of the implementation.

## 9. Replay and crash semantics

The generic sink **claims the capability before invoking the external effect**.

That prevents the dangerous sequence:

`effect happens → process crashes → capability never marked consumed → replay duplicates effect`

The trade-off is that a crash after consumption but before external effect can produce `consumed / no effect`. This implementation deliberately favors **at-most-once safety** over automatic retry.

For stronger recovery semantics use the target system's actual atomic primitive:

- transactional outbox;
- database transaction;
- ledger transaction ID;
- idempotency key equal to `capability_id`;
- device-resident atomic consume-and-release primitive.

A generic library cannot truthfully promise exactly-once effect across arbitrary independent systems.

## 10. System and latency variations

`configs/system_profiles.json` includes profiles for:

| Profile | Example target |
|---|---:|
| embedded control | 100 µs |
| accelerator hot path | 500 µs |
| UPF/SmartNIC egress | 1 ms |
| API gateway | 2 ms |
| storage writer | 5 ms |
| payment finality | 10 ms |
| cross-region governance | 20 ms |
| audit-heavy output | 50 ms |

These are **engineering targets**, not fabricated performance claims. `scripts/benchmark.py` records actual runtime/environment and reports p50/p95/p99/max. The Python reference is for correctness and interoperability; native/device-resident implementations are appropriate for the tightest targets.

## 11. Cross-language interoperability

The repository avoids the weak situation where “Python signs what Python later verifies.”

`vectors/interop.json` now contains **20 deterministic positive vectors** with canonical UTF-8 strings, SHA-256 digests and HMAC-SHA256 results. Independent Python, Node.js and Go implementations reproduce and verify them. `vectors/canonicalization_conformance.json` adds **9 focused conformance/rejection cases**.

The portable security-bound JSON profile is intentionally narrow:

- UTF-8;
- Unicode NFC normalization of string values **and object keys in Python, Node.js and Go**;
- collision rejection after key normalization;
- key ordering by Unicode scalar / valid UTF-8 lexical order;
- deterministic compact JSON string escaping;
- integers restricted to `-(2^53-1)` through `+(2^53-1)` for portable material;
- floats/NaN/Infinity rejected;
- bytes and unsupported runtime-specific values excluded from the portable profile.

The Go verifier vendors `golang.org/x/text/unicode/norm` so NFC conformance does not depend on assuming pre-normalized input or on a network fetch. See `docs/CANONICALIZATION_PROFILE.md` for the exact rules and the distinction between the Python-local and cross-language portable profiles.

A production standard should normatively specify a canonical format (or use a well-specified binary representation) rather than relying on implementation-default JSON behavior.

## 12. Cryptography

The dependency-free default uses HMAC-SHA256 for deterministic tests and language interoperability. It is **not** a recommendation to share one symmetric key across unrelated trust domains.

An optional Ed25519 adapter is included. Production deployment should normally separate:

- authority capability/evidence signing key;
- presenter proof-of-possession key;
- sink finality-receipt key.

Where appropriate, place keys in an HSM, TEE, secure element, TPM-backed service or device security domain.

## 13. Relationship to existing security mechanisms

The architecture is more credible when positioned as **complementary**, not as a claim that everything existing is obsolete.

OAuth/RAR/DPoP can provide granular authorization and presenter proof. RATS can supply environment evidence. TEEs/HSMs can protect authority/sink keys and state. OPA/policy engines can evaluate policy. Database/ledger transactions can give stronger effect-specific atomicity. Network/device controls can make the sink non-bypassable.

The distinctive invariant demonstrated here is the combination of:

**exact non-effective Candidate Act → protected validation/evidence/state → bounded authority → independent local verification at the effect boundary → single-use consumption → external consequence.**

See `docs/THREAT_MODEL.md` for a detailed comparison and residual risks.

## 14. What would falsify the architecture in a real deployment

A deployment should be considered **not finality-enforced** if any of the following is true:

- an externally effective path exists that does not traverse a protected sink;
- the sink trusts caller-supplied sink/boundary identity instead of local identity;
- the effect can occur before verification/consumption;
- capability replay can produce a second consequence;
- validation evidence can be substituted without detection;
- protected-state rollback can reactivate spent authority;
- fail-open behavior occurs on verifier/state/evidence failure;
- “non-bearer” is claimed while theft of a serialized capability alone is sufficient under the stated threat model;
- benchmark targets are claimed without measurements on the target deployment.

These are intentionally severe acceptance criteria.

## 15. Current measured reference benchmark

The recorded benchmark uses 1,000 warm-up iterations followed by 3,000 measured iterations. The exact p50/p95/p99/max values are stored in `benchmarks/reference-python-local.json` rather than duplicated here because user-space scheduling noise can materially change a rerun even on the same visible environment. The repository therefore treats benchmark output as a reproducible measurement artifact, not a deterministic real-time guarantee.

The benchmark artifact now records Python, kernel, libc, CPU string visible through `/proc`, visible CPU count/affinity, memory, SQLite, OpenSSL, Node, Go and key Python tool versions. See `benchmarks/reference-python-local.json` and `docs/REFERENCE_ENVIRONMENT.md`. These are environment-specific measurements, not certified hardware/telecom/accelerator/payment performance claims.

## 16. Documentation

- `docs/ARCHITECTURE.md` — code-to-foundational-chain mapping and invariants.
- `docs/IMPLEMENTATION_DETAILS.md` — derivation, languages, parameters, profiles, methodology and non-claims.
- `docs/CANONICALIZATION_PROFILE.md` — exact Python/Go/Node portable serialization rules and conformance cases.
- `docs/REFERENCE_ENVIRONMENT.md` — recorded tool/runtime/system configuration and interpretation limits.
- `docs/source/FUNDAMENTAL_ARCHITECTURE_FIG_1A-1C.pdf` — supplied three-page source architecture drawing.
- `docs/THREAT_MODEL.md` — adversaries, sink attacks, residual risks and comparison to adjacent controls.
- `docs/RED_TEAM_FINDINGS.md` — issues found by attacking the design rather than defending it rhetorically.
- `docs/DEPLOYMENT.md` — making the sink actually non-bypassable.
- `docs/SECURITY.md` — production-hardening checklist.
- `docs/LIMITATIONS.md` — explicit non-claims.
- `docs/BENCHMARKING.md` — latency methodology.
- `docs/TEST_MATRIX.md` — automated coverage.
- `docs/attack_matrix.csv` — machine-readable attack inventory.
- `environment/reference-environment.json` — machine-readable environment snapshot.
- `requirements-tested.txt` — exact direct Python tool versions used for the recorded run.

## 17. Licensing / patent note
CC-BY-NC- 4.0 INTERNATIONAL , Commerfcial details in IETF Disclosure 


## IMPLEMENTATION_DETAILS ( Reference ) 


Execution-Finality Foundational Architecture — Full Reference Implementation Methodology
This document explains how the hardened reference implementation was derived, what languages and cryptographic profiles were used, which parameters and system variations were exercised, how the 481-test verification campaign was structured, how the benchmark was produced, what the threat model covers, and—equally importantly—what the implementation does not prove.

The implementation is intended to make the foundational execution-finality architecture executable, inspectable, reproducible, and falsifiable. It is not a claim that a Python process by itself creates a hardware non-bypassability boundary, nor is it a claim of universal production certification.

1. Objective
The implementation tests the following architectural invariant:

A consequence-bearing operation may be computed, prepared, buffered, queued, ranked, simulated, encrypted, sealed, or otherwise processed, but it remains non-effective until the exact Candidate Act is independently verified by the Finality Sink controlling the corresponding external-effect boundary.

The implementation therefore distinguishes computation from authority and separates authorization from effectuation.

2. Derivation from FIG. 1A–1C
The implementation follows the supplied three-stage foundational drawing rather than beginning with a conventional token framework and renaming components.

The implemented sequence is:

Compute / Workload Plane → Candidate Act → Non-Effective Hold → Protected Authority / PED → HCAD → Protected Predicate Validation → Protected-State Transition → Validation Evidence / LAVR → Scoped Capability → Finality Sink → Sink-Side Descriptor Reconstruction → Independent Verification → Capability Consumption → Sink Receipt → External Effect

The Candidate Act is initially non-effective. The protected authority validates predicates and advances protected state. Evidence is committed before or atomically with capability availability. The Finality Sink independently reconstructs the local descriptor, verifies the exact Candidate Act and all load-bearing bindings, consumes the capability, and only then permits the external effect.

3. Exact architecture-to-code mapping
Foundational architecture element	Runnable implementation
Compute / Workload Plane	Any producer capable of constructing CandidateAct
Candidate Act	Immutable CandidateAct dataclass
Non-Effective State	ActStatus.NON_EFFECTIVE
Protected Authority / PED	ProtectedAuthority
HCAD / machine-verifiable descriptor	HCAD + build_hcad()
Protected Predicate Validation	Policy.validate()
Protected State	ProtectedState
Protected State Transition	StateTransition
Validation Evidence / LAVR	ValidationEvidence
Evidence commitment	EvidenceStore
Scoped capability	Capability
Strict non-bearer profile	PresentationProof
Finality Sink	FinalitySink
Sink-side descriptor reconstruction	Sink-local build_hcad()
Replay consumption	InMemoryConsumptionStore / SQLiteConsumptionStore
Effect boundary	Guarded effectors
Output / finality receipt	SinkReceipt
External effect	Bound effect handle invoked only after sink verification and claim
4. Why the implementation is not just authorize() → token → execute()
The reference keeps decision, state, evidence, authority, presentation, sink verification, replay consumption, and effectuation as separately represented stages. This allows tests to mutate each stage independently and determine whether the effect boundary still fails closed.

A signature alone is never treated as sufficient. The sink verifies semantic consistency among the Candidate Act, HCAD, policy epoch, evidence, protected-state transition, sink identity, boundary identity, nonce, scope, and time bounds.

5. Programming languages used
Three runtimes are intentionally included:

Runtime	Role
Python 3.11+	Complete readable reference implementation
Go 1.23.2	Independent infrastructure-oriented verifier
Node.js 22.16.0	Independent application/runtime verifier
Python contains the complete state machine. Go and Node independently reproduce the portable canonicalization and verify deterministic cryptographic and finality vectors.

6. Why Python was chosen for the complete reference
Python was selected for auditability and readability, not because it is asserted to be the optimal production implementation for every latency class.

The Python implementation exposes every transition explicitly: Candidate creation, descriptor generation, policy validation, state update, evidence commitment, capability construction, presenter proof, sink reconstruction, replay claim, effect invocation, and finality receipt.

For a 100-µs device or accelerator path, a production implementation would more plausibly be native code, firmware, kernel code, SmartNIC/DPU logic, FPGA logic, or another device-resident implementation.

7. Why independent Go verification was added
A single-language test can be self-consistent while still being wrong. Python could serialize a structure incorrectly and another Python function could reproduce the same mistake.

Go therefore independently verifies canonicalization, SHA-256, HMAC, and complete portable Finality Sink vectors. Go is also relevant to networking, gateways, cloud infrastructure, sidecars, telecom components, and control-plane software.

The Go Unicode-normalization dependency is vendored so conformance tests can run without internet access.

8. Why independent Node.js verification was added
Node.js was included because JavaScript/TypeScript ecosystems are common in APIs, AI-agent tool systems, service gateways, application runtimes, and cloud control planes.

Node independently performs NFC normalization, portable canonical serialization, SHA-256, HMAC verification, and complete Finality Sink vector verification.

The Node canonicalizer explicitly avoids relying on JavaScript's ordinary UTF-16 lexical ordering for security-bound object keys.

9. Candidate Act data model
The Candidate Act represents the concrete proposed consequence, not merely a generic permission.

Parameter	Meaning
act_id	Candidate identifier
act_class	Operation type
effect_class	External consequence class
source	Workload/agent/service generating the act
destination	Exact consequence destination
purpose	Authorized purpose
jurisdiction	Applicable jurisdiction
policy_epoch	Policy version
nonce	Replay-resistant nonce
issued_at_ns	Candidate creation time
freshness_ns	Candidate validity interval
sink_id	Intended Finality Sink
boundary_id	Intended effect boundary
scope	Exact permitted operation scope
payload	Exact proposed action/data
runtime_evidence_digest	Runtime/attestation evidence binding
authority_context	Additional authority context
status	Initially NON_EFFECTIVE
10. Deterministic test Candidate parameters
A stable reference Candidate is used for deterministic tests.

Parameter	Test value
Act class	api-call
Effect class	network-egress
Source	agent-A
Destination	https://example.invalid/payments
Purpose	approved-purpose
Jurisdiction	EU
Policy epoch	7
Sink	sink-A
Boundary	boundary-A
Scope	POST:/payments
Payload amount	1000 minor units
Currency	EUR
Beneficiary	B1
Runtime evidence	runtime-ok
Freshness	10,000,000,000 ns (10 s)
Status	NON_EFFECTIVE
The deterministic test clock uses NOW = 1,800,000,000,000,000,000 ns, and a typical Candidate is issued 10,000 ns before NOW. This removes wall-clock nondeterminism from security tests.

11. HCAD / machine-verifiable act descriptor
The HCAD binds structured consequence context including act class, effect class, source, destination, purpose, jurisdiction, policy epoch, nonce, issuance/freshness information, Finality Sink, boundary, scope, payload digest, and runtime-evidence digest.

The implementation uses both a whole-Candidate digest and a structured descriptor digest. This provides independent detection of Candidate mutation and semantic descriptor mismatch.

12. Canonicalization profile
Security-bound structures use a deliberately narrow canonical profile:

UTF-8 encoding;

Unicode NFC normalization;

deterministic object-key ordering;

compact deterministic JSON representation;

floats rejected;

NaN and infinity rejected;

non-string map keys rejected;

duplicate keys created by Unicode normalization rejected;

portable integers restricted to JavaScript's exact integer range, ±(2^53−1);

unpaired surrogate values rejected;

arbitrary bytes rejected from the portable cross-language JSON profile.

The local Python canonical form and the narrower Python/Go/Node portable profile are explicitly distinguished.

13. Canonicalization security rationale
Canonicalization prevents cryptographic disagreement caused by whitespace, object-key order, Unicode-equivalent forms, float rendering, parser differences, duplicate-normalized keys, and alternate serialization.

The purpose is not to invent a universal wire standard. The reference demonstrates one constrained profile. A standards-track version should define a normative canonical encoding or adopt an established canonical binary/JSON representation.

14. Policy parameters
The reference policy includes the following example configuration:

Parameter	Reference configuration
Policy epoch	7
Purposes	approved-purpose, diagnostic, render
Jurisdictions	EU, US, IN
Sinks	sink-A, sink-B
Boundaries	boundary-A, boundary-B
Required runtime evidence	runtime-ok
Maximum future-clock skew	1,000,000,000 ns (1 s)
Reference scopes include POST:/payments, WRITE:/records, DISPLAY, PUBLISH, SEND, SPAWN, ACTUATE, SETTLE, DMA:RELEASE, and QUEUE:PUBLISH.

These are demonstration parameters, not normative limits.

15. Protected predicate validation
The policy rejects, among other conditions:

Candidate not in NON_EFFECTIVE state;

incorrect policy epoch;

unauthorized purpose;

unauthorized jurisdiction;

unauthorized sink;

unauthorized boundary;

unsupported effect class;

unauthorized or empty scope;

duplicate scope;

revoked source;

stale Candidate;

future-dated Candidate beyond permitted skew;

invalid freshness;

wrong runtime-evidence digest.

Additional real deployments may add consent, legal basis, ALF/RBD identity, device posture, transaction risk, model identity, data classification, and other predicates.

16. Protected-state parameters
ProtectedState models state that should reside in a rollback-resistant or protected location in production.

State item	Reference default
Monotonic version	starts at 0
Quota	1,000
Budget	1,000
Authorization cost	1
A successful authorization advances state:

version N → N+1

quota Q → Q−1

budget B → B−cost

The state transition identifier cryptographically incorporates the relevant before/after values, nonce, source, epoch, and Candidate digest.

17. Evidence-before-capability ordering
The implementation deliberately performs:

validate Candidate
    ↓
advance protected state
    ↓
construct ValidationEvidence
    ↓
sign evidence
    ↓
commit evidence
    ↓
construct/sign capability
    ↓
make capability available
It does not issue authority first and attempt to log evidence later. If evidence commitment fails, the operation fails closed and no usable capability is returned.

18. Validation Evidence / LAVR representation
The reference evidence includes:

Field	Binding
evidence_id	Cryptographic evidence identity
authority_id	Authority issuing the decision
descriptor_digest	Exact HCAD
candidate_digest	Exact Candidate
transition_id	Protected-state transition
policy_epoch	Policy version
decision	ALLOW/DENY semantic
reasons	Decision rationale
committed_at_ns	Commitment time
key_id	Signing-key identity
signature	Cryptographic authentication
The evidence store rejects invalid signatures and duplicate evidence identifiers.

19. Capability construction
The scoped capability binds:

authority identity;

Candidate digest;

descriptor digest;

sink identity;

boundary identity;

nonce;

permitted scope;

policy epoch;

evidence identifier;

protected-state transition identifier;

issue time;

expiry;

signing-key identity.

The default maximum capability TTL is 5,000,000,000 ns (5 s). Actual expiry is the minimum of Candidate freshness expiry and authority TTL expiry, so capability issuance cannot extend Candidate freshness.

20. Cryptographic choices and key roles
The dependency-light baseline uses SHA-256 for digests and HMAC-SHA256 for deterministic authentication.

HMAC is used because Python, Go, and Node can independently reproduce the vectors with minimal dependencies. It is not a recommendation to share one symmetric key across unrelated trust domains.

The repository also includes optional Ed25519 support using cryptography.

Production systems should normally separate at least:

Key role	Purpose
Authority key	Capability/evidence signing
Presenter key	Proof of possession
Sink key	Finality-receipt signing
21. Strict non-bearer / proof-of-possession profile
Red-team analysis identified that act-bound + sink-bound + single-use does not automatically make an artifact non-bearer. An attacker stealing the exact Candidate and exact unused capability could potentially race the legitimate presenter.

The strict profile therefore binds a presenter identity and requires a fresh proof over:

capability identifier;

Candidate digest;

sink identifier;

boundary identifier;

nonce;

presentation timestamp;

presenter key identifier.

Default presentation freshness is 2,000,000,000 ns (2 s). Tests explicitly reject proofs just outside both positive and negative freshness windows.

22. Finality Sink local configuration
The Finality Sink owns its own local context, including:

Sink-local property	Example
Sink ID	sink-A
Boundary ID	boundary-A
Policy epoch	7
Supported scopes	locally configured
Effect class	locally configured
The caller is not allowed to dictate the sink's identity. The sink uses local configuration when reconstructing the HCAD.

23. Finality Sink verification sequence
The sink approximately verifies:

Candidate remains NON_EFFECTIVE
→ effect class matches local sink
→ Candidate sink matches local sink
→ capability sink matches local sink
→ Candidate boundary matches local boundary
→ capability boundary matches local boundary
→ Candidate epoch matches local epoch
→ capability epoch matches local epoch
→ Candidate scope matches capability scope
→ scope is locally supported
→ nonce matches
→ capability time is valid
→ capability does not outlive Candidate
→ capability signature is valid
→ optional presenter proof is valid and fresh
→ Candidate digest matches reconstructed Candidate
→ HCAD is rebuilt using local sink/boundary
→ descriptor digest matches locally rebuilt descriptor
→ evidence exists
→ evidence signature is valid
→ evidence decision is ALLOW
→ evidence authority matches capability authority
→ evidence Candidate matches capability Candidate
→ evidence descriptor matches capability descriptor
→ evidence state transition matches capability state transition
→ evidence epoch matches capability epoch
→ protected-state transition is valid
→ capability is claimed/consumed
→ external effect is invoked
This is intentionally stronger than signature valid → allow.

24. Why sink reconstruction is independent
The Finality Sink does not simply trust an upstream assertion that the descriptor was already checked. It reconstructs the effect context using sink-owned identity, boundary, epoch, effect class, and scope configuration.

This allows the sink to detect cross-sink laundering, wrong-boundary presentation, local epoch mismatch, unsupported scope, post-authorization Candidate mutation, and semantically inconsistent but validly re-signed artifacts.

25. Replay protection implementations
Two replay/consumption backends are included.

In-memory: a lock protects capability claim state.

SQLite durable: the reference uses SQLite 3.46.1, WAL journal mode, capability_id as the primary key, BEGIN IMMEDIATE for the claim transaction, and a 30-second connection timeout.

Duplicate capability identifiers are converted into replay rejection.

26. Concurrency and replay test parameters
Replay is exercised under contention.

Test	Contenders / attempts
In-memory concurrent race	2, 3, 4, 8, 16, 32, 64
SQLite concurrent race	2, 4, 8, 16, 32
Sequential replay attempts	2, 3, 5, 10, 25
The expected invariant is that exactly one contender may create the effect; every other contender must be rejected.

27. Consume-before-effect crash semantics
The reference uses:

VERIFY → CLAIM/CONSUME → EXTERNAL EFFECT

rather than:

VERIFY → EXTERNAL EFFECT → CONSUME

This chooses at-most-once safety and avoids the failure mode where an effect occurs, the process crashes before consumption, and a retry produces a duplicate effect.

The opposite residual is explicitly documented: capability consumption may succeed and the process may crash before the external effect occurs, producing consumed / no effect.

Systems requiring stronger exactly-once semantics should bind capability_id to a target-native transaction, idempotency key, ledger transaction identifier, transactional outbox, or device-resident atomic consume-and-release primitive.

28. Executable guarded effectors
Nine consequence-boundary simulations are implemented:

Consequence	Reference effector
Network transmission	NetworkEffector
Storage mutation	StorageEffector
Rendering	RendererEffector
Message queue	QueueEffector
Process spawning	ProcessEffector
Actuation	ActuatorEffector
Payment/ledger	PaymentEffector
AI/model output	ModelOutputEffector
DMA/memory release	DMAEffector
The ordinary public effect path rejects direct invocation; the sink receives a private bound handle. This proves the reference API seam, not physical non-bypassability against privileged attackers.

29. Wide-channel deployment threat model
A larger deployment model covers 20 consequence channels:

network-egress, storage-write, renderer, message-queue, process-spawn, actuator, payment-ledger, model-output, DMA/memory-release, webhook, email-send, SMS-send, radio-transmit, ledger-bridge, file-export, clipboard, print-spool, socket-egress, shared-memory-release, device-command.

Every declared channel records whether it is externally effective, sink mediated, protected by an enforcement boundary, and privileged.

Externally effective non-mediated paths are treated as critical. Missing or non-privileged enforcement boundaries are separately flagged.

30. System/deployment variations
Eight reference deployment profiles are included:

Profile	Example sink	Latency target	Example enforcement
Embedded control	actuator	100 µs	MCU / secure element
Accelerator hot path	DMA/memory release	500 µs	GPU/DPU/SmartNIC
UPF egress	network	1 ms	UPF/N6 or SmartNIC
API gateway	network	2 ms	reverse proxy/gateway
Storage writer	storage	5 ms	transactional writer
Payment finality	ledger	10 ms	payment/ledger bridge
Cross-region governance	network	20 ms	regional gateway
Audit-heavy output	model output	50 ms	controlled emitter
The latency values are engineering stress bands, not vendor specifications or normative requirements.

31. Hot path versus cold path
The architecture does not require every expensive security operation to occur on the hot path.

Cold-path examples: remote attestation collection, certificate-chain validation, policy retrieval, policy compilation, trust-anchor verification, configuration distribution.

Hot-path examples: local descriptor reconstruction, digest/signature verification, local epoch/state lookup, replay claim, effect commit.

Very tight latency targets generally require precomputation and execution near the actual protected effect boundary.

32. Exact Python test count
The hardened implementation contains 481 collected Python tests.

Test module/category	Tests
Binding integrity	66
Canonicalization	54
Consequence channels	36
Concurrency/replay	17
Core architecture	11
Defensive branches	13
Ed25519	2
Fail-closed/fault injection	16
Seeded fuzz mutations	76
Interoperability	37
Non-bearer/PoP	13
Policy matrix	35
System profiles	17
Key-role separation	2
Finality Sink adversarial	43
Wide-channel surface	43
TOTAL	481
The recorded hardened run reports 481 passed.

33. Binding-mutation test methodology
Tests mutate load-bearing Candidate fields after authorization, including act ID, act class, effect class, source, destination, purpose, jurisdiction, policy epoch, nonce, issue time, freshness, sink, boundary, scope, runtime evidence, and authority context.

Payload tests independently alter amount, currency, beneficiary, missing/extra fields, zero/negative values, large integers, nested structures, reordered lists, type changes, case changes, and whitespace-sensitive values.

The original capability must never authorize the changed Candidate.

34. Re-signed semantic attack testing
Many adversarial tests do not merely corrupt signatures. They alter capability or evidence fields and then re-sign the malicious artifact with a valid reference key.

This tests whether the sink validates semantics rather than using the weak rule valid signature = valid authority.

Re-signed attacks target authority, Candidate digest, descriptor digest, sink, boundary, nonce, scope, epoch, evidence identifier, state transition, and timing values.

35. Seeded fuzz / variation testing
The suite contains 76 deterministic seeded mutation tests. Sixty deterministic seeds mutate payment-like payload properties; additional cases mutate destination and other context properties.

Fixed seeds make failures reproducible.

This is not claimed to be coverage-guided fuzzing such as AFL/libFuzzer or a complete stateful property-fuzz campaign.

36. Policy variation testing
Policy tests cover combinations and boundary values for:

jurisdictions EU, US, IN;

purposes approved-purpose, diagnostic, render;

quota and budget boundary values;

valid and over-budget costs;

source revocation sets;

correct and incorrect epochs;

valid, zero, stale, and future freshness;

correct, empty, duplicate, and unauthorized scopes;

correct and incorrect runtime evidence.

Purpose × jurisdiction alone creates a 3 × 3 cross-product.

37. Finality Sink adversarial parameters
Sink-focused tests exercise wrong sink IDs, wrong boundaries, wrong epochs, restricted scopes, multiple valid and invalid time points, altered destinations, altered scopes, and sinks configured with the wrong authority verification material.

Adversarial epoch values include 0, 1, 6, 8, 9, 2^31−1, covering ordinary off-by-one conditions and extreme values.

38. Cross-language interoperability vectors
The hardened repository includes 20 positive deterministic interoperability vectors verified independently by Python, Node, and Go.

The vectors exercise canonical representation, UTF-8 bytes, SHA-256, and HMAC-SHA256.

Additional vectors deliberately cover decomposed Unicode values, decomposed Unicode keys, BMP-versus-supplementary-plane key ordering, JSON control characters, <, >, &, U+2028/U+2029, and canonical-equivalent forms.

39. Canonicalization conformance suite
A separate 9-case canonicalization conformance suite contains five required-success cases and four required-rejection cases.

It includes NFC key collision, float rejection, integers outside the portable safe range, and other malformed/ambiguous inputs.

Node and Go independently execute the conformance suite; corresponding Python tests cover the same profile.

40. Cross-language complete Finality Sink vectors
Two complete portable finality cases are included:

a baseline Candidate;

a Candidate containing decomposed Unicode inside load-bearing material.

Node and Go independently reconstruct and verify:

Candidate → payload digest → HCAD → Candidate digest → protected-state transition → validation evidence → capability → sink-local context → Finality Sink verification.

This prevents the implementation from relying on Python to generate and verify its own artifacts exclusively.

41. Statement coverage
The hardened run reports:

724 Python source statements;

0 statements missed;

100% statement coverage.

Representative command:

pytest --cov=src/finality_ref --cov-report=term-missing:skip-covered -q
This does not mean 100% security coverage. It means every measured executable Python statement was exercised by the test suite.

42. Benchmark methodology and parameters
The benchmark uses time.perf_counter_ns() and performs 1,000 warm-up iterations followed by 3,000 measured iterations per path.

Three paths are measured:

canonicalization + SHA-256;

Finality Sink verification only;

complete authority + sink + guarded effectuation.

The benchmark Candidate uses a network-egress act from bench-agent to example.invalid/effect, purpose bench, jurisdiction EU, epoch 1, sink bench-sink, boundary bench-boundary, scope SEND, runtime evidence runtime-ok, 60-second Candidate freshness, 30-second capability TTL, and quota/budget of 1,000,000 to prevent benchmark exhaustion.

43. Recorded reference environment and benchmark results
The hardened reference environment records:

Environment item	Recorded value
Python	CPython 3.13.5
Kernel	Linux 6.18.35
Architecture	x86-64
libc	glibc 2.41
CPU string visible	AMD EPYC 9V74 80-Core Processor
CPU vendor	AuthenticAMD
Logical CPUs visible	5
Process affinity	CPUs 0–4
Visible memory	6,236,925,952 bytes
SQLite	3.46.1
OpenSSL	3.5.5
Node.js	22.16.0
Node ICU	77.1
Go	1.23.2 linux/amd64
pytest	9.0.2
pytest-cov	7.0.0
coverage	7.13.3
cryptography	46.0.4
setuptools	82.0.1
The recorded benchmark results are:

Operation	Mean	p50	p95	p99	Maximum
Canonical SHA-256	7.98 µs	7.12 µs	8.90 µs	29.37 µs	233.75 µs
Sink verify only	215.32 µs	197.30 µs	287.84 µs	504.20 µs	1,314.27 µs
Authority + sink + effect	1,113.22 µs	1,054.97 µs	1,350.46 µs	1,847.28 µs	4,037.53 µs
These are reproducible user-space Python reference measurements, not certified production measurements for GPU, DPU, telecom, payment, embedded, or other target hardware.

The benchmark does not establish controlled CPU frequency, turbo state, cache topology, NUMA placement, power governor, core isolation, virtualization contention, or dedicated accelerator usage.

44. Threat model, limitations, and what is deployment-required
The threat model includes Candidate mutation, destination substitution, purpose/jurisdiction substitution, scope expansion, sink and boundary substitution, cross-sink laundering, epoch rollback, stale/future capabilities, evidence mutation/deletion, protected-state substitution, sequential and parallel replay, capability theft, confused-deputy presentation, canonicalization disagreement, Unicode collision, downstream crash, direct raw-socket bypass, direct database bypass, renderer/debug leakage, DMA/P2P bypass, hidden consequence channels, sink compromise, key compromise, denial of service, and covert channels.

The package distinguishes:

TESTED — directly exercised in executable tests;

MITIGATED — design reduces risk but residual remains;

DEPLOYMENT_REQUIRED — cannot be solved by the user-space reference alone;

RESIDUAL / OUT_OF_SCOPE — explicitly unresolved.

Principal limitations include:

Python is not a hardware security boundary.

The repository cannot automatically discover every hidden effect path.

HMAC is reference/interoperability crypto, not a universal production key-distribution recommendation.

Vendor-specific RATS/TPM/TEE/GPU attestation verification remains pluggable rather than fabricated.

Exactly-once consequences are not universally guaranteed.

Timing/cache/RF/power and other covert or physical side channels are outside the model.

A fully compromised privileged Finality Sink remains a fundamental threat.

Python memory alone cannot provide hardware rollback resistance.

The canonical JSON profile is deliberately narrow and should become a normative wire profile in a standards-track implementation.

Runtime Unicode-data versions differ; the current conformance claim is tied to the defined profile and included repertoire, not every future Unicode code point.

Latency profiles are targets/stress bands, not guarantees.

481 tests and 100% statement coverage do not prove absence of unknown vulnerabilities.

The implementation is an engineering realization and does not by itself establish patent scope or legal claim construction.

Actual non-bypassability requires that every consequence-bearing path converge on a privileged Finality Sink or equivalent enforcement boundary.

A real deployment should be considered incomplete if a raw socket, alternate database credential, unmediated renderer, DMA mapping, message-broker credential, direct file writer, or other external-effect path can bypass the Finality Sink.

45. Reproduction, falsifiability, and supportable conclusion
Representative complete verification commands are:

python3 -m compileall -q src
pytest -q

node node/verify.mjs vectors/interop.json
node node/canonical_conformance.mjs vectors/canonicalization_conformance.json
node node/finality_verify.mjs vectors/finality_case.json
node node/finality_verify.mjs vectors/finality_case_unicode.json

cd go
go test -mod=vendor ./...
go vet -mod=vendor ./...
go run -mod=vendor . ../vectors/interop.json
go run -mod=vendor ./cmd/canonicalconformance ../vectors/canonicalization_conformance.json
go run -mod=vendor ./cmd/finalityverify ../vectors/finality_case.json
go run -mod=vendor ./cmd/finalityverify ../vectors/finality_case_unicode.json

python3 examples/demo.py
python3 examples/strict_non_bearer.py
python3 scripts/benchmark.py
The architecture is intentionally falsifiable. A claimed deployment should fail review if an external effect can bypass the sink, if sink identity is caller-controlled, if effect occurs before final verification, if replay can produce a second consequence, if evidence or protected state can be substituted without rejection, if epoch downgrade is accepted, if scope can be enlarged, if a claimed strict non-bearer capability works through mere possession, or if the claimed sink is only a user-space wrapper around an otherwise unrestricted effect path.

The supportable conclusion from the current hardened package is:

The foundational Execution-Finality architecture has been converted into an executable state machine in which exact Candidate Acts remain non-effective until protected validation, protected-state advancement, evidence commitment, scoped authority generation, sink-local descriptor reconstruction, independent effect-time verification, replay consumption, and guarded effectuation occur. The implementation has been exercised through hundreds of deterministic adversarial tests, concurrency races, failure injections, canonicalization attacks, cross-language verifiers, and system/deployment variations. Actual deployment non-bypassability still depends on locating the Finality Sink at the real privileged consequence boundary.

Verification summary
Python tests: 481 passed

Python source statement coverage: 724/724 statements exercised (100%)

Cross-language positive vectors: 20

Canonicalization conformance cases: 9

Complete Finality Sink vectors: 2

Independent runtimes: Python + Node.js + Go

Concurrent replay testing: up to 64 contenders

Wide-channel deployment model: 20 consequence channels

Executable consequence simulations: 9

Deployment/latency profiles: 8 profiles from 100 µs to 50 ms

Benchmark: 1,000 warm-up + 3,000 measured iterations per path
