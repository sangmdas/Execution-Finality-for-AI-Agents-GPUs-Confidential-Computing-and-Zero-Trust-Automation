from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Protocol

from .canonical import canonical_bytes


class Authenticator(Protocol):
    key_id: str
    def sign(self, value: Any) -> str: ...
    def verify(self, value: Any, signature: str, key_id: str) -> bool: ...


@dataclass(frozen=True)
class HMACAuthenticator:
    """Deterministic reference authenticator.

    HMAC is deliberately used for dependency-free interop vectors. In a deployment
    spanning trust domains, replace this with an HSM/TEE-backed asymmetric signer.
    """
    key: bytes
    key_id: str = "reference-hmac-sha256-v1"

    def sign(self, value: Any) -> str:
        return hmac.new(self.key, canonical_bytes(value), hashlib.sha256).hexdigest()

    def verify(self, value: Any, signature: str, key_id: str) -> bool:
        if key_id != self.key_id or not isinstance(signature, str):
            return False
        expected = self.sign(value)
        return hmac.compare_digest(expected, signature)


class Ed25519Authenticator:
    """Optional asymmetric authenticator backed by `cryptography`.

    A verifier may be constructed with only a public key. Signatures are hex encoded
    so the same model interfaces are used as the dependency-free HMAC reference.
    """
    def __init__(self, *, key_id: str, private_key=None, public_key=None):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError as exc:
            raise RuntimeError("install the 'crypto' extra to use Ed25519Authenticator") from exc
        if private_key is None and public_key is None:
            private_key = Ed25519PrivateKey.generate()
        self._private = private_key
        self._public = public_key or private_key.public_key()
        self.key_id = key_id

    @classmethod
    def generate(cls, key_id: str = "ed25519-v1"):
        return cls(key_id=key_id)

    def verifier(self):
        return Ed25519Authenticator(key_id=self.key_id, public_key=self._public)

    def sign(self, value: Any) -> str:
        if self._private is None:
            raise RuntimeError("verifier-only Ed25519Authenticator cannot sign")
        return self._private.sign(canonical_bytes(value)).hex()

    def verify(self, value: Any, signature: str, key_id: str) -> bool:
        if key_id != self.key_id:
            return False
        try:
            raw = bytes.fromhex(signature)
            self._public.verify(raw, canonical_bytes(value))
            return True
        except Exception:
            return False
