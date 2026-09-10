.PHONY: test interop conformance bench all

test:
	PYTHONPATH=src pytest -q

interop:
	node node/verify.mjs vectors/interop.json
	node node/finality_verify.mjs vectors/finality_case.json
	node node/finality_verify.mjs vectors/finality_case_unicode.json
	cd go && go run -mod=vendor . ../vectors/interop.json
	cd go && go run -mod=vendor ./cmd/finalityverify ../vectors/finality_case.json
	cd go && go run -mod=vendor ./cmd/finalityverify ../vectors/finality_case_unicode.json

conformance:
	node node/canonical_conformance.mjs vectors/canonicalization_conformance.json
	cd go && go run -mod=vendor ./cmd/canonicalconformance ../vectors/canonicalization_conformance.json

bench:
	PYTHONPATH=src python3 scripts/benchmark.py --iterations 5000 --output benchmarks/latest.json

all:
	./scripts/run_all.sh
