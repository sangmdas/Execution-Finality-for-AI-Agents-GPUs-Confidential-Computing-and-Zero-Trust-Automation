from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import sqlite3
import ssl
import statistics
import subprocess
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from finality_ref.authority import ProtectedAuthority
from finality_ref.canonical import sha256_hex
from finality_ref.crypto import HMACAuthenticator
from finality_ref.effectors import NetworkEffector
from finality_ref.evidence import EvidenceStore
from finality_ref.models import CandidateAct, SinkContext
from finality_ref.policy import Policy
from finality_ref.sink import FinalitySink
from finality_ref.state import InMemoryConsumptionStore, ProtectedState

NOW = 1_800_000_000_000_000_000


def percentile(values, p):
    v = sorted(values)
    idx = min(len(v) - 1, max(0, int(round((len(v) - 1) * p))))
    return v[idx] / 1000.0


def summary(ns_values):
    return {
        "n": len(ns_values),
        "mean_us": statistics.fmean(ns_values) / 1000.0,
        "p50_us": percentile(ns_values, .50),
        "p95_us": percentile(ns_values, .95),
        "p99_us": percentile(ns_values, .99),
        "min_us": min(ns_values) / 1000.0,
        "max_us": max(ns_values) / 1000.0,
    }


def _first_proc_value(label: str) -> str | None:
    path = Path("/proc/cpuinfo")
    if not path.exists():
        return None
    prefix = label + "\t"
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith(prefix) or line.startswith(label + " "):
            return line.split(":", 1)[1].strip() if ":" in line else None
    return None


def _mem_total_bytes() -> int | None:
    path = Path("/proc/meminfo")
    if not path.exists():
        return None
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2:
                return int(parts[1]) * 1024
    return None


def _cmd_version(argv: list[str]) -> str | None:
    try:
        return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=5).stdout.strip()
    except Exception:
        return None


def _pkg_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def environment_snapshot() -> dict:
    libc_name, libc_version = platform.libc_ver()
    affinity = None
    if hasattr(os, "sched_getaffinity"):
        try:
            affinity = sorted(os.sched_getaffinity(0))
        except OSError:
            pass
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "python_unicode_data": unicodedata.unidata_version,
        "platform": platform.platform(),
        "kernel_release": platform.release(),
        "machine": platform.machine(),
        "processor_reported_by_platform": platform.processor() or None,
        "cpu_model_from_proc": _first_proc_value("model name"),
        "cpu_vendor_from_proc": _first_proc_value("vendor_id"),
        "logical_cpu_count_visible": os.cpu_count(),
        "process_cpu_affinity": affinity,
        "memory_total_bytes_visible": _mem_total_bytes(),
        "libc": {"name": libc_name or None, "version": libc_version or None},
        "sqlite": sqlite3.sqlite_version,
        "openssl": ssl.OPENSSL_VERSION,
        "node": _cmd_version(["node", "--version"]),
        "node_unicode_data": _cmd_version(["node", "-p", "process.versions.unicode"]),
        "node_icu": _cmd_version(["node", "-p", "process.versions.icu"]),
        "go": _cmd_version(["go", "version"]),
        "go_unicode_data_recorded": "15.0.0 (Go 1.23.2 unicode.Version in the recorded environment)",
        "go_vendored_x_text": "v0.16.0",
        "pytest": _pkg_version("pytest"),
        "pytest_cov": _pkg_version("pytest-cov"),
        "coverage": _pkg_version("coverage"),
        "cryptography": _pkg_version("cryptography"),
        "setuptools": _pkg_version("setuptools"),
        "environment_note": (
            "Values describe the execution container visible to the benchmark. "
            "CPU model may identify the underlying or virtualized host CPU; no bare-metal, "
            "frequency, NUMA, cache, governor, isolation, or dedicated-accelerator claim is inferred."
        ),
    }


def make_candidate(i):
    return CandidateAct(
        act_id=f"bench-{i}", act_class="api-call", effect_class="network-egress",
        source="bench-agent", destination="https://example.invalid/effect",
        purpose="bench", jurisdiction="EU", policy_epoch=1, nonce=f"n-{i}",
        issued_at_ns=NOW, freshness_ns=60_000_000_000, sink_id="bench-sink",
        boundary_id="bench-boundary", scope=("SEND",), payload={"i": i, "v": "x" * 16},
        runtime_evidence_digest="runtime-ok", authority_context={"bench": True},
    )


def build():
    auth = HMACAuthenticator(b"benchmark-reference-key")
    evidence = EvidenceStore(auth)
    state = ProtectedState(default_quota=1_000_000, default_budget=1_000_000)
    policy = Policy(
        1, frozenset({"bench"}), frozenset({"EU"}), frozenset({"bench-sink"}),
        frozenset({"bench-boundary"}), frozenset({"network-egress"}),
        frozenset({"SEND"}), required_runtime_evidence_digest="runtime-ok"
    )
    authority = ProtectedAuthority(
        authority_id="bench-authority", policy=policy, state=state,
        evidence_store=evidence, authenticator=auth,
        capability_ttl_ns=30_000_000_000, clock=lambda: NOW
    )
    eff = NetworkEffector()
    sink = FinalitySink(
        context=SinkContext("bench-sink", "bench-boundary", 1, frozenset({"SEND"}), "network-egress"),
        authenticator=auth, evidence_store=evidence, protected_state=state,
        consumption_store=InMemoryConsumptionStore(), effect_handle=eff.bind_for_sink(), clock=lambda: NOW
    )
    return authority, sink


def run(iterations):
    authority, sink = build()
    c0 = make_candidate(-1)
    cap0 = authority.authorize(c0)
    # Warm caches/interpreter paths before timed samples.
    for _ in range(1000):
        sink.verify(c0, cap0)
        sha256_hex({"x": 1, "y": "abc"})
    digest_times = []
    verify_times = []
    end_to_end = []
    for _ in range(iterations):
        t = time.perf_counter_ns()
        sha256_hex({"candidate": "abc", "epoch": 1, "scope": ["SEND"]})
        digest_times.append(time.perf_counter_ns() - t)
        t = time.perf_counter_ns()
        sink.verify(c0, cap0)
        verify_times.append(time.perf_counter_ns() - t)
    for i in range(iterations):
        c = make_candidate(i)
        t = time.perf_counter_ns()
        cap = authority.authorize(c)
        sink.effectuate(c, cap)
        end_to_end.append(time.perf_counter_ns() - t)
    return {
        "schema": "execution-finality-reference-benchmark-v2",
        "environment": environment_snapshot(),
        "iterations": iterations,
        "warmup_iterations": 1000,
        "clock": "time.perf_counter_ns",
        "measurements": {
            "canonical_sha256": summary(digest_times),
            "sink_verify_only": summary(verify_times),
            "authority_plus_sink_effectuation": summary(end_to_end),
        },
        "warning": (
            "User-space Python reference numbers are illustrative, not certified latency guarantees. "
            "Hardware/native deployments require independent measurement on the actual target stack."
        ),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iterations', type=int, default=5000)
    ap.add_argument('--output')
    args = ap.parse_args()
    result = run(args.iterations)
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text)
    print(text)


if __name__ == '__main__':
    main()
