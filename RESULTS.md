# Verification Results

## Automated suite

**481 passed** in the recorded build environment.

The suite includes exact-act and descriptor binding, protected evidence/state, policy/freshness, cross-sink/boundary laundering, direct-effect bypass, wide-channel coverage, concurrent replay, durable SQLite claims, failure injection, Unicode/canonicalization hardening, seeded mutation fuzzing, strict proof-of-possession and role-key separation.

Recorded Python source statement coverage: **100% (724 statements, 0 missed)**.

## Cross-language positive vectors

- Python: **20/20** deterministic vectors as pytest parameterized cases.
- Node.js: **20/20** verified.
- Go: **20/20** verified.

The vectors bind canonical UTF-8 bytes to SHA-256 and HMAC-SHA256 expected values and include deliberately decomposed Unicode, normalized object keys, supplementary-plane key ordering and JSON escaping cases.

## Canonicalization conformance/rejection suite

- Python: **9/9** cases represented in pytest (5 accept + 4 required rejection cases).
- Node.js: **9/9** verified.
- Go: **9/9** verified.

The Go implementation now performs NFC normalization itself using a vendored `golang.org/x/text/unicode/norm` dependency. This closes the earlier conformance weakness where Go could pass the original vectors without proving behavior on decomposed Unicode input.

## Portable Finality Sink verification

- Node.js portable Finality Sink verification: **PASS**.
- Go portable Finality Sink verification: **PASS**.

These verifiers independently reconstruct and check the portable Candidate Act / HCAD / protected-state transition / validation evidence / capability / sink-context chain.

## Local Python benchmark (3,000 measured iterations)

The current recorded run used 1,000 warm-up iterations and `time.perf_counter_ns`.

| Operation | p50 | p95 | p99 | max |
| --- | ---: | ---: | ---: | ---: |
| Canonical SHA-256 | 7.120 us | 8.904 us | 29.365 us | 233.753 us |
| Sink verification only | 197.298 us | 287.844 us | 504.201 us | 1314.265 us |
| Authority + sink + guarded effect | 1054.973 us | 1350.459 us | 1847.279 us | 4037.528 us |

See `benchmarks/reference-python-local.json` for raw values and the full observed environment. These numbers are illustrative user-space Python measurements, not certified latency guarantees for hardware, telecom, accelerator, payment, embedded or cross-region deployments.

## Red-team conclusion

The reference makes the architecture executable and falsifiable, but it deliberately does not claim that a user-space library can prevent bypass when an attacker retains an unrestricted alternative effect path. The strongest deployment requirement remains: **all consequence-bearing paths must converge on a privileged Finality Sink or equivalent effect boundary.**
