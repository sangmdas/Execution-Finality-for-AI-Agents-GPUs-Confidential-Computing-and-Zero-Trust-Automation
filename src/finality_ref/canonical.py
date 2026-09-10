from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import asdict, is_dataclass
from typing import Any


class CanonicalizationError(ValueError):
    pass


MAX_SAFE_INTEGER = 2**53 - 1


def _normalize(value: Any, *, portable: bool = False) -> Any:
    if is_dataclass(value):
        value = asdict(value)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        # The local Python reference can represent arbitrary integers. The
        # explicitly cross-language portable profile is narrower so JavaScript,
        # Go and Python cannot silently disagree about numeric identity.
        if portable and not (-MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER):
            raise CanonicalizationError("integer outside portable safe range")
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floating point values are forbidden in security-bound material")
    if isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise CanonicalizationError("unpaired UTF-16 surrogate code point is forbidden")
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bytes):
        if portable:
            raise CanonicalizationError("bytes are not part of the portable JSON profile")
        return {"$bytes_hex": value.hex()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v, portable=portable) for v in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, val in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("dictionary keys must be strings")
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in key):
                raise CanonicalizationError("unpaired UTF-16 surrogate code point is forbidden in key")
            nkey = unicodedata.normalize("NFC", key)
            if nkey in out:
                raise CanonicalizationError("key collision after Unicode normalization")
            out[nkey] = _normalize(val, portable=portable)
        return {k: out[k] for k in sorted(out)}
    raise CanonicalizationError(f"unsupported value type: {type(value).__name__}")


def _dump(normalized: Any) -> bytes:
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_bytes(value: Any) -> bytes:
    """Canonical bytes used by the Python reference implementation.

    This local profile permits arbitrary Python integers and a tagged bytes
    extension. Use portable_canonical_bytes for material that must be reproduced
    exactly by the Go and Node interoperability implementations.
    """
    return _dump(_normalize(value, portable=False))


def portable_canonical_bytes(value: Any) -> bytes:
    """Cross-language canonical profile used by Python/Go/Node vectors.

    It NFC-normalizes strings and keys, rejects key collisions after
    normalization, rejects floats and bytes, and limits integers to +/- (2^53-1).
    """
    return _dump(_normalize(value, portable=True))


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
