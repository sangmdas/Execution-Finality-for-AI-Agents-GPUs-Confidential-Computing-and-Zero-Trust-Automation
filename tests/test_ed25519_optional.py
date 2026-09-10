from __future__ import annotations

from finality_ref.crypto import Ed25519Authenticator


def test_ed25519_sign_verify_round_trip():
    signer = Ed25519Authenticator.generate("authority-ed25519")
    verifier = signer.verifier()
    value = {"candidate":"abc","epoch":7}
    sig = signer.sign(value)
    assert verifier.verify(value, sig, "authority-ed25519")
    assert not verifier.verify({"candidate":"xyz","epoch":7}, sig, "authority-ed25519")


def test_ed25519_key_id_is_bound():
    signer = Ed25519Authenticator.generate("authority-ed25519")
    sig = signer.sign({"x":1})
    assert not signer.verifier().verify({"x":1}, sig, "wrong-key")
