# Execution-Finality Reference Architecture

## Normative reference chain implemented here

The implementation follows the supplied FIG. 1A–1C sequence rather than treating authorization as a generic token check.

| Drawing step | Reference implementation |
|---|---|
| 100 Compute/workload plane | Any producer may create a `CandidateAct`. The producer is not trusted to cause effect. |
| 102 Candidate Act | `CandidateAct`, always created as `NON_EFFECTIVE`. |
| 104 Hold state | The act is a data object. No effector is invoked during preparation/validation. |
| 106 Protected authority / PED | `ProtectedAuthority`, `ProtectedState`, pluggable authenticators and runtime-evidence policy. |
| 108 HCAD | `build_hcad()` canonicalizes security-relevant act/effect/source/destination/purpose/jurisdiction/epoch/nonce/freshness/sink/boundary/scope/payload/evidence fields. |
| 110 Predicate validation | `Policy.validate()` plus protected quota/budget/nonce checks. |
| 112/116 Fail closed | `ValidationDenied`; no capability is returned. State/evidence failures burn availability rather than create an effect path. |
| 118 State update | `ProtectedState.transition_for_authorization()` reserves nonce and advances monotonic/quota/budget state. |
| 120 LAVR/evidence commitment | `EvidenceStore.commit()` persists signed validation evidence before capability return. |
| 122 Scoped capability | `Capability` binds exact candidate digest, HCAD digest, sink, boundary, nonce, scope, epoch, evidence, and protected-state transition. |
| 124 Finality Sink | `FinalitySink`. It has local sink/boundary/effect-class/scope context. |
| 126 Sink-side descriptor | Sink rebuilds the HCAD using its *local* sink and boundary identity. |
| 128 Sink verification | Signature, candidate, descriptor, sink, boundary, nonce, scope, epoch, evidence, freshness, protected state and optional proof-of-possession are independently checked. |
| 132/136 Sink failure | Exception + no effector invocation. |
| 130 Capability consumption | `InMemoryConsumptionStore` or `SQLiteConsumptionStore` claims capability before effect. |
| 137 Output LAVR | `SinkReceipt`, optionally signed under a key separate from authority keys. |
| 138 Effective act | Only a sink-bound guarded effector can record the simulated external effect. |

## Core invariants

**I-1 — Computation is not authority.** Creating or computing an act does not make it externally effective.

**I-2 — Exact-act binding.** Any material mutation after authorization invalidates the capability. Payload changes are bound by payload digest and whole-candidate digest.

**I-3 — Local finality identity.** The sink does not trust a caller-supplied sink/boundary descriptor; it rebuilds the descriptor with local identity.

**I-4 — Evidence-before-capability.** A capability is not returned until protected validation evidence has been committed.

**I-5 — Protected-state binding.** The capability references a concrete state transition. The sink verifies the transition against the Candidate Act.

**I-6 — Single use.** A capability is claimed before effect; replay races resolve to one winner.

**I-7 — Fail closed.** Missing/tampered/stale/mismatched state, evidence, capability or sink context produces no effect.

**I-8 — Strict non-bearer profile.** When proof-of-possession mode is enabled, possession of a stolen capability plus Candidate Act is insufficient. A fresh presenter proof bound to the capability, candidate, sink, boundary and nonce is also required.

**I-9 — Wide-channel completeness.** The protocol protects only effect paths actually routed through a Finality Sink. `DeploymentManifest` treats any declared unguarded externally effective path as CRITICAL.

## Why the Finality Sink is not redundant

Validation answers whether a proposed act is admissible at a decision point. It does not by itself prove that the exact bytes/arguments/target ultimately sent to an external system are unchanged, that the same policy epoch is still in force, that the intended sink is being used, or that the authorization has not already been consumed. The sink therefore performs a second, local verification at the point where non-effect becomes effect.

This is deliberately analogous to separating a policy decision point from an enforcement point, but the reference adds exact Candidate Act binding, sink/boundary binding, protected evidence/state references and single-use finality semantics.

## Capability terminology

A capability that is only highly constrained but can still be replayed by any holder of the capability and exact Candidate Act should not be called strictly non-bearer under a strong attacker model. For that reason the repository includes an explicit proof-of-possession profile (`pop.py`). The basic act-bound mode is useful for protocol testing, while the strict profile requires presenter proof.
