# Limitations — Claims the Reference Does Not Make

1. **Python is not a hardware security boundary.** The guarded effector is an executable model of the interface, not proof against a root/host attacker.
2. **Topology completeness is external.** An undeclared alternate effect path bypasses the architecture. The manifest audit helps make the assumption visible but cannot discover all paths by itself.
3. **HMAC is a test/interop primitive here.** Use asymmetric keys and protected key storage across trust domains. An optional Ed25519 adapter is included.
4. **Runtime attestation is modeled as evidence binding.** Vendor-specific RATS/TPM/TEE/GPU attestation verification is intentionally pluggable, not fabricated.
5. **No universal exactly-once guarantee.** Cross-system atomicity requires transaction/idempotency support from the consequence system.
6. **No covert-channel elimination.** Timing/cache/RF/power and other side channels are outside this finality model.
7. **No automatic protection against a fully compromised privileged sink.** Minimize and attest the sink TCB.
8. **Canonical JSON profile is intentionally narrow.** Floats are rejected; arbitrary application serialization needs a formally specified canonical representation.
9. **Latency targets are engineering targets, not guarantees.** The benchmark reports the executing environment; production targets require measurement on the target stack.
10. **No claim that adjacent standards are inadequate.** OAuth/RAR/DPoP, RATS, TEEs, policy engines, database transactions and network/device controls can implement or complement parts of the architecture.
11. **Patent scope is not established by this code.** The repository demonstrates one implementation pattern and should not be treated as a legal claim-construction document.

12. **Unicode data versions are not exhaustively pinned across all runtimes.** The recorded Python, Node and Go runtimes use different Unicode data releases. The included decomposed-Unicode and key-ordering vectors pass in all three implementations, but arbitrary newly assigned code points are not exhaustively proven. A standards-track profile should pin the normalization repertoire/version or use one normative canonicalization implementation.
13. **Vector JSON is transport, not a complete arbitrary-JSON parser specification.** The portable canonicalizer is defined over typed values. A production wire protocol must also define duplicate-key handling, numeric lexical forms and parser behavior.
