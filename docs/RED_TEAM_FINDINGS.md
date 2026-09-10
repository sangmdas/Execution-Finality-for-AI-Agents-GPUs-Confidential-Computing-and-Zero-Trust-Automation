# Red-Team Findings

## Findings that materially changed the implementation

### RT-01 — “Act-bound” alone is not strict non-bearer
A thief possessing the exact Candidate Act and exact unconsumed capability could race the legitimate presenter. **Change:** optional mandatory proof-of-possession mode with fresh presenter proof. Documentation distinguishes constrained act-bound mode from strict non-bearer mode.

### RT-02 — A user-space sink is bypassable if raw effect paths remain
A Python wrapper cannot stop a process with direct socket/DB/device privileges. **Change:** guarded-effect seam plus machine-readable deployment surface audit; documentation requires privileged/topological enforcement.

### RT-03 — Consume-after-effect creates a duplicate race
If the external effect occurs and the process crashes before consumption, replay can duplicate it. **Change:** reference claims capability before effect. Residual availability gap is documented.

### RT-04 — Consume-before-effect cannot guarantee exactly once across independent systems
Crash after consumption can lose an intended effect. **Change:** explicitly choose at-most-once safety; prescribe durable outbox/idempotency/transaction coupling where exactly-once semantics are required.

### RT-05 — Sink must not trust caller-provided sink identity
A caller could reconstruct a descriptor for another sink if local identity is not injected. **Change:** sink rebuilds HCAD with its own sink and boundary identity.

### RT-06 — A valid signature is not enough
A compromised/misissued signing path could produce structurally inconsistent artifacts. **Change:** sink checks every load-bearing binding independently even when signatures verify. Tests re-sign mutated artifacts to prove this.

### RT-07 — One shared key collapses trust roles
If authority, presenter and receipt signing all use one key, compromise propagates. **Change:** sink supports separate receipt key; strict PoP uses separate presenter key; asymmetric/HSM deployment recommended.

### RT-08 — Canonicalization can become the exploit
Float/NaN behavior, Unicode normalization and map ordering can create cross-language disagreement. **Change:** floats are rejected, Unicode NFC is applied, normalized-key collisions are rejected, and deterministic vectors are verified in three languages.

### RT-09 — Known-channel testing can still miss a hidden channel
A successful test suite cannot prove no undeclared egress exists. **Change:** this is stated as a deployment assumption rather than hidden behind test results.

### RT-10 — Latency claims without target-hardware measurements are bluff-prone
Microbenchmark numbers from a development VM cannot substantiate DPU/GPU/telecom hardware targets. **Change:** measured environment is recorded, targets are profiles, and no benchmark target is marked certified.
