# Automated Test Matrix

The clean current collection contains **481 pytest cases**. These are collected tests/parameterized cases rather than one test function looping through hundreds of assertions.

## Exact collected distribution

| Test module | Cases |
| --- | ---: |
| `test_binding_integrity.py` | 66 |
| `test_canonicalization.py` | 54 |
| `test_channels.py` | 36 |
| `test_concurrency.py` | 17 |
| `test_core.py` | 11 |
| `test_defensive_branches.py` | 13 |
| `test_ed25519_optional.py` | 2 |
| `test_fail_closed.py` | 16 |
| `test_fuzz_mutations.py` | 76 |
| `test_interop.py` | 37 |
| `test_non_bearer_pop.py` | 13 |
| `test_policy_matrix.py` | 35 |
| `test_profiles.py` | 17 |
| `test_role_key_separation.py` | 2 |
| `test_sink_adversarial.py` | 43 |
| `test_wide_channel_surface.py` | 43 |
| **TOTAL** | **481** |

The exact count can always be regenerated with:

```bash
pytest --collect-only -q
```

## Security categories covered

- Core Candidate Act -> non-effective -> authority -> evidence -> capability -> sink -> effect ordering.
- Policy predicates: purpose, jurisdiction, epoch, runtime evidence, freshness, revocation, quota and budget.
- Candidate/HCAD/capability/evidence binding mutation matrix.
- Finality Sink substitution, shadow sink, boundary substitution, local epoch and local scope attacks.
- Direct-effector bypass tests for network, storage, renderer, queue, process, actuator, payment, model output and DMA/memory release.
- Wide-channel deployment surface audit across twenty consequence channels.
- Replay and concurrency races, including SQLite durable single-use claims and up to 64 contenders.
- Failure injection: evidence persistence failure and downstream effect failure after consumption.
- Canonicalization ambiguity, Unicode NFC equivalence, normalized-key collision, JSON escaping, key-ordering differences, integer range and malformed signatures.
- Seeded payload/destination mutation fuzz cases.
- Strict non-bearer proof-of-possession attacks.
- Cross-language deterministic vectors and portable Finality Sink verification in Python, Node.js and Go.
- Optional Ed25519 signature round trips and cryptographic role-key separation.

## Cross-language canonicalization material

The current interop set contains **20 positive vectors**. A separate canonicalization file contains **9 cases**: five positive hardening cases and four required rejections. The Go verifier now performs actual NFC normalization using a vendored Unicode normalization implementation rather than assuming pre-normalized input.

## Recorded statement coverage

The verification run collected the following coverage over `src/finality_ref`:

```text
TOTAL: 724 statements, 0 missed, 100% statement coverage
```

Coverage was generated with:

```bash
pytest --cov=src/finality_ref --cov-report=term-missing:skip-covered -q
```

The current run reaches 100% statement coverage, but coverage percentage is not treated as a security proof. A high line percentage cannot establish deployment non-bypassability, complete threat coverage, or absence of semantic vulnerabilities; the adversarial test categories remain more important than the raw percentage.
