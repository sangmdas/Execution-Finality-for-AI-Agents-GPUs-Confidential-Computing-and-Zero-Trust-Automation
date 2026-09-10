# Build Checkpoint

Status: hardened runnable reference package completed and locally verified.

Verification performed in the recorded environment:

- Python: **3.13.5**
- Go: **1.23.2**
- Node.js: **22.16.0**
- pytest: **481 passed**
- Python source statement coverage: **100% (724 statements, 0 missed)**
- Deterministic interop vectors: **20/20 Node.js**, **20/20 Go**, plus Python parameterized verification
- Canonicalization conformance: **9/9 Node.js**, **9/9 Go**, plus Python accept/reject verification
- Portable Finality Sink case: **PASS in Node.js and Go**
- Example normal finality flow: passed
- Example strict proof-of-possession/non-bearer flow: passed
- Benchmark artifact: `benchmarks/reference-python-local.json` (1,000 warm-up + 3,000 measured iterations)
- Source FIG. 1A-1C drawing included under `docs/source/`
- Exact environment snapshot included under `environment/`
- Exact direct Python test/tool versions included in `requirements-tested.txt`
- Go Unicode normalization dependency vendored; verification uses `-mod=vendor`

Resume command after interruption:

```bash
cd finality-reference-implementation
python -m pip install -e '.[dev,crypto]'
./scripts/run_all.sh
```

Security posture is intentionally conservative: tests establish behavior of this reference implementation, not mathematical proof of all deployments. Non-bypassability requires real mediation of every consequence-bearing path at the target system's privileged effect boundary.
