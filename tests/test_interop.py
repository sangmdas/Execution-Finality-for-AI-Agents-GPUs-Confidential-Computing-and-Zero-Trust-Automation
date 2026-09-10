from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from pathlib import Path
import pytest

from finality_ref.canonical import CanonicalizationError, portable_canonical_bytes

ROOT = Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT / "vectors" / "interop.json").read_text(encoding="utf-8"))
CONF = json.loads((ROOT / "vectors" / "canonicalization_conformance.json").read_text(encoding="utf-8"))
KEY = bytes.fromhex(DATA["key_hex"])

@pytest.mark.parametrize("vector", DATA["vectors"], ids=lambda v: v["id"])
def test_python_interop_vectors(vector):
    c = portable_canonical_bytes(vector["value"])
    assert c.decode("utf-8") == vector["canonical_utf8"]
    assert hashlib.sha256(c).hexdigest() == vector["sha256"]
    assert hmac.new(KEY, c, hashlib.sha256).hexdigest() == vector["hmac_sha256"]


@pytest.mark.parametrize("case", CONF["positive"], ids=lambda v: v["id"])
def test_python_canonicalization_conformance_positive(case):
    assert portable_canonical_bytes(case["value"]).decode("utf-8") == case["canonical_utf8"]


@pytest.mark.parametrize("case", CONF["negative"], ids=lambda v: v["id"])
def test_python_canonicalization_conformance_negative(case):
    with pytest.raises(CanonicalizationError):
        portable_canonical_bytes(case["value"])


def test_node_verifier_accepts_all_vectors():
    result = subprocess.run(
        ["node", str(ROOT / "node" / "verify.mjs"), str(ROOT / "vectors" / "interop.json")],
        capture_output=True, text=True, check=True,
    )
    assert "20/20" in result.stdout


def test_go_verifier_accepts_all_vectors():
    result = subprocess.run(
        ["go", "run", "-mod=vendor", ".", str(ROOT / "vectors" / "interop.json")],
        cwd=ROOT / "go", capture_output=True, text=True, check=True,
    )
    assert "20/20" in result.stdout


def test_node_canonicalization_conformance():
    result = subprocess.run(
        ["node", str(ROOT / "node" / "canonical_conformance.mjs"), str(ROOT / "vectors" / "canonicalization_conformance.json")],
        capture_output=True, text=True, check=True,
    )
    assert "9/9" in result.stdout


def test_go_canonicalization_conformance():
    result = subprocess.run(
        ["go", "run", "-mod=vendor", "./cmd/canonicalconformance", str(ROOT / "vectors" / "canonicalization_conformance.json")],
        cwd=ROOT / "go", capture_output=True, text=True, check=True,
    )
    assert "9/9" in result.stdout


def test_node_portable_finality_sink_verifier():
    result = subprocess.run(
        ["node", str(ROOT / "node" / "finality_verify.mjs"), str(ROOT / "vectors" / "finality_case.json")],
        capture_output=True, text=True, check=True,
    )
    assert "PASS" in result.stdout


def test_go_portable_finality_sink_verifier():
    result = subprocess.run(
        ["go", "run", "-mod=vendor", "./cmd/finalityverify", str(ROOT / "vectors" / "finality_case.json")],
        cwd=ROOT / "go", capture_output=True, text=True, check=True,
    )
    assert "PASS" in result.stdout

def test_node_portable_finality_sink_verifier_unicode_input():
    result = subprocess.run(
        ["node", str(ROOT / "node" / "finality_verify.mjs"), str(ROOT / "vectors" / "finality_case_unicode.json")],
        capture_output=True, text=True, check=True,
    )
    assert "PASS" in result.stdout


def test_go_portable_finality_sink_verifier_unicode_input():
    result = subprocess.run(
        ["go", "run", "-mod=vendor", "./cmd/finalityverify", str(ROOT / "vectors" / "finality_case_unicode.json")],
        cwd=ROOT / "go", capture_output=True, text=True, check=True,
    )
    assert "PASS" in result.stdout

