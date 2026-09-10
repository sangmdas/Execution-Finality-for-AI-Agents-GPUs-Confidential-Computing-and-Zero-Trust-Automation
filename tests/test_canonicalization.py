from __future__ import annotations

import unicodedata
import pytest

from finality_ref.canonical import MAX_SAFE_INTEGER, CanonicalizationError, canonical_bytes, portable_canonical_bytes, sha256_hex


@pytest.mark.parametrize("a,b", [
    ({"a":1,"b":2}, {"b":2,"a":1}),
    ({"z":{"b":2,"a":1},"a":0}, {"a":0,"z":{"a":1,"b":2}}),
    ({"x":[{"b":2,"a":1}]}, {"x":[{"a":1,"b":2}]}),
    ({"é":"café"}, {unicodedata.normalize("NFD", "é"): unicodedata.normalize("NFD", "café")}),
    ({"bool":True,"none":None,"n":1}, {"n":1,"none":None,"bool":True}),
])
def test_semantically_identical_supported_values_canonicalize_identically(a,b):
    assert canonical_bytes(a) == canonical_bytes(b)
    assert sha256_hex(a) == sha256_hex(b)


@pytest.mark.parametrize("value", [0.0, 1.5, float("inf"), float("-inf"), float("nan")])
def test_floats_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"x": value})


@pytest.mark.parametrize("value", [
    {1:"x"}, {None:"x"}, {(1,2):"x"}, {b"x":"y"},
])
def test_non_string_dict_keys_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)


@pytest.mark.parametrize("value", [
    set([1,2]), object(), complex(1,2), lambda: None,
])
def test_unsupported_types_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)


@pytest.mark.parametrize("value", [
    "", "ascii", "é", "e\u0301", "日本語", "हिन्दी", "العربية", "emoji-🔐",
    "nul-\u0000", "line\nbreak", "tab\tvalue", "quote\"slash\\", "<>&",
])
def test_strings_canonicalize_deterministically(value):
    assert canonical_bytes({"v":value}) == canonical_bytes({"v":value})


@pytest.mark.parametrize("n", [0,1,-1,2**31-1,2**31,2**63-1,-2**63,10**100])
def test_integer_boundaries_are_stable(n):
    assert sha256_hex({"n":n}) == sha256_hex({"n":n})


@pytest.mark.parametrize("n", [0, 1, -1, MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER])
def test_portable_integer_boundaries_are_stable(n):
    assert portable_canonical_bytes({"n": n}) == portable_canonical_bytes({"n": n})


@pytest.mark.parametrize("n", [MAX_SAFE_INTEGER + 1, -(MAX_SAFE_INTEGER + 1), 10**100])
def test_portable_integers_outside_safe_range_are_rejected(n):
    with pytest.raises(CanonicalizationError):
        portable_canonical_bytes({"n": n})

def test_unicode_key_collision_after_normalization_is_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"é": 1, "e\u0301": 2})


@pytest.mark.parametrize("value", ["\ud800", "\udc00"])
def test_unpaired_surrogate_code_points_are_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"v": value})
    with pytest.raises(CanonicalizationError):
        portable_canonical_bytes({"v": value})


def test_local_bytes_extension_is_explicit_and_deterministic():
    assert canonical_bytes({"blob": b"\x00\xff"}) == b'{"blob":{"$bytes_hex":"00ff"}}'


def test_portable_profile_rejects_bytes_extension():
    with pytest.raises(CanonicalizationError):
        portable_canonical_bytes({"blob": b"\x00\xff"})


def test_unpaired_surrogate_in_object_key_is_rejected():
    with pytest.raises(CanonicalizationError):
        portable_canonical_bytes({"\ud800": "x"})


def test_sha256_bytes_hashes_exact_bytes():
    import hashlib
    from finality_ref.canonical import sha256_bytes
    data = b"exact-security-bytes"
    assert sha256_bytes(data) == hashlib.sha256(data).hexdigest()
