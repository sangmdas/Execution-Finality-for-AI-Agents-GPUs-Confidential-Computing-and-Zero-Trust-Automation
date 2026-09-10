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

No open-source license is selected automatically by this generated package. Read `LICENSE-NOTICE.md` before publishing. Source availability should not accidentally be presented as granting patent rights unless that is the repository owner's deliberate licensing decision.
