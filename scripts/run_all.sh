#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
python3 -m compileall -q src
pytest -q
node node/verify.mjs vectors/interop.json
node node/canonical_conformance.mjs vectors/canonicalization_conformance.json
node --check node/canonical.mjs
node --check node/verify.mjs
node --check node/canonical_conformance.mjs
node --check node/finality_verify.mjs
node node/finality_verify.mjs vectors/finality_case.json
node node/finality_verify.mjs vectors/finality_case_unicode.json
(cd go && go test -mod=vendor ./...)
(cd go && go vet -mod=vendor ./...)
(cd go && go run -mod=vendor . ../vectors/interop.json)
(cd go && go run -mod=vendor ./cmd/canonicalconformance ../vectors/canonicalization_conformance.json)
(cd go && go run -mod=vendor ./cmd/finalityverify ../vectors/finality_case.json)
(cd go && go run -mod=vendor ./cmd/finalityverify ../vectors/finality_case_unicode.json)
python3 examples/demo.py >/dev/null
python3 examples/strict_non_bearer.py >/dev/null
python3 scripts/benchmark.py --iterations "${BENCH_ITERATIONS:-1000}" --output benchmarks/latest.json >/dev/null
printf 'All reference checks passed.\n'
