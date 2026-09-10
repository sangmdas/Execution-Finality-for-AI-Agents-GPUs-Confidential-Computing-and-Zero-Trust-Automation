# Recorded Reference Environment

This file records the environment used for the current reproducibility run. It is deliberately descriptive rather than promotional. The values are not hardware performance promises and must not be generalized to GPU, DPU, SmartNIC, telecom, payment, embedded or production systems.

## Visible test environment

- Python: **3.13.5 (CPython)**; Unicode data **15.1.0**
- Kernel: **Linux 6.18.35**
- Architecture: **x86-64 / amd64**
- libc: **glibc 2.41**
- CPU model reported through `/proc/cpuinfo`: **AMD EPYC 9V74 80-Core Processor**
- CPU vendor reported through `/proc/cpuinfo`: **AuthenticAMD**
- Logical CPUs visible to the container: **5**
- Visible process affinity in the recorded run: **CPUs 0–4**
- Memory visible through `/proc/meminfo`: approximately **5.81 GiB**
- SQLite: **3.46.1**
- OpenSSL: **3.5.5 (27 Jan 2026)**
- Node.js: **22.16.0**; Unicode data **16.0**, ICU **77.1**
- Go: **1.23.2 linux/amd64**; Go `unicode.Version` **15.0.0**; vendored `x/text` **v0.16.0**
- pytest: **9.0.2**
- pytest-cov: **7.0.0**
- coverage.py: **7.13.3**
- cryptography: **46.0.4**
- setuptools: **82.0.1**

A machine-readable snapshot is stored at `../environment/reference-environment.json`.

## Important interpretation limits

The CPU string may identify an underlying or virtualized host processor. The reference run does **not** establish that the process had an entire physical 80-core processor, bare-metal access, a fixed clock frequency, deterministic cache residency, NUMA pinning, isolated cores, a performance governor, real-time scheduling, or a dedicated crypto accelerator.

Only five logical CPUs were visible to this container. The benchmark therefore reports the environment as observed by the process and does not infer unavailable topology.

## Exact direct Python tool versions

`../requirements-tested.txt` records the exact direct package versions used for the verification run. `pyproject.toml` intentionally retains compatible minimums for ordinary development, while the tested requirements file provides a reproducibility snapshot.

The Python HMAC core has no mandatory third-party runtime dependency. `cryptography` is optional and is used for the Ed25519 adapter/tests.

## Go reproducibility

The Go verifier requires NFC normalization. To avoid a future network fetch changing the behavior, the repository vendors `golang.org/x/text v0.16.0` from the tested Go toolchain distribution. See `../go/THIRD_PARTY_NOTICES.md` and the preserved third-party license.

The verification commands use `-mod=vendor`, making the recorded Go conformance test independent of network availability.

## Benchmark methodology

The recorded benchmark is stored at `../benchmarks/reference-python-local.json` and includes its own environment snapshot. It uses `time.perf_counter_ns`, 1,000 warm-up iterations and 3,000 measured iterations for each reported path.

The measurements are user-space Python measurements. They are useful for detecting implementation regressions and showing that the path is executable. They are not a substitute for target-specific benchmark work under realistic contention, scheduling, device, network and persistence conditions.

## Unicode reproducibility qualification

The three runtimes do not expose the same Unicode-data release. The interoperability claim is therefore tied to the included conformance vectors and tested character repertoire. The repository does not claim exhaustive equivalence for every code point introduced across Unicode versions. See `CANONICALIZATION_PROFILE.md` for the standards-track recommendation to pin a normalization repertoire/version or one normative canonicalizer.
