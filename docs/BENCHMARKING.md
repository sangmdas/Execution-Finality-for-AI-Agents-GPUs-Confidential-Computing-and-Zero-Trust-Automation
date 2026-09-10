# Benchmarking and Latency Targets

Run a fresh measurement with:

```bash
python scripts/benchmark.py --iterations 5000 --output benchmarks/result.json
```

The checked-in recorded result uses 1,000 warm-up iterations and 3,000 measured iterations:

`benchmarks/reference-python-local.json`

## Measured paths

The benchmark separately measures:

- canonical SHA-256 binding cost;
- Finality Sink verification-only cost;
- protected-authority + sink + guarded-effect path.

The benchmark uses `time.perf_counter_ns` and reports mean, p50, p95, p99, minimum and maximum. The artifact also records the visible runtime/system environment, including Python, kernel, libc, CPU string, visible CPU count/affinity, memory, SQLite, OpenSSL, Node, Go, Unicode-data versions and principal Python tool versions.

## Why the repository does not hard-code one latency claim

The system profiles range from approximately 100 us to 50 ms. Those values are **engineering/deployment stress targets**, not claims that the Python reference meets every target.

User-space benchmark results can move materially between runs because of scheduler load, interpreter/runtime state, CPU sharing, cache state, frequency changes and container/host contention. This is why the raw result file is treated as the measurement source of truth instead of repeating a single attractive number throughout the documentation.

For serious performance evaluation record at minimum:

- exact processor/environment visible to the process;
- architecture and OS/kernel;
- runtime/compiler versions;
- crypto provider and key location;
- state backend and persistence mode;
- descriptor/Candidate size;
- number of concurrent workers;
- CPU affinity/isolation and scheduler policy where relevant;
- cold versus warm cache state;
- p50/p95/p99/max and throughput;
- whether remote attestation, policy retrieval or certificate-chain verification occurred on the hot path;
- effect-system latency versus finality-verification latency.

A 100-us-class profile should normally use native/device-resident code, local protected state and precomputed descriptor fragments. Cross-region or audit-heavy profiles can afford larger verification/evidence work.

No benchmark in this repository is a certified performance statement for a GPU, DPU, SmartNIC, telecom UPF, payment system, storage engine, embedded controller or production cloud deployment.
