from __future__ import annotations

from dataclasses import replace
import random
import string
import pytest

from finality_ref.errors import VerificationFailed
from .conftest import make_stack


def _mutate_payload(payload, seed):
    r = random.Random(seed)
    p = dict(payload)
    mode = seed % 8
    if mode == 0:
        p["amount_minor"] = p["amount_minor"] + r.randint(1, 1_000_000)
    elif mode == 1:
        p["beneficiary"] = "B-" + "".join(r.choice(string.ascii_letters) for _ in range(8))
    elif mode == 2:
        p["currency"] = r.choice(["USD", "JPY", "INR", "GBP", "eur", "EUR "])
    elif mode == 3:
        p["injected"] = {"seed": seed, "nested": [seed, seed + 1]}
    elif mode == 4:
        p.pop("beneficiary", None)
    elif mode == 5:
        p["beneficiary"] = [p.get("beneficiary"), seed]
    elif mode == 6:
        p["amount_minor"] = -abs(int(p["amount_minor"])) - seed
    else:
        p["memo"] = f"mutation-{seed}-🔐"
    return p


@pytest.mark.parametrize("seed", list(range(60)))
def test_seeded_payload_mutation_never_reuses_original_authorization(seed):
    c, _, _, _, authority, eff, sink = make_stack()
    cap = authority.authorize(c)
    mutated = replace(c, payload=_mutate_payload(c.payload, seed))
    with pytest.raises(VerificationFailed):
        sink.effectuate(mutated, cap)
    assert not eff.records


@pytest.mark.parametrize("suffix", [
    "/alt", "?admin=true", "#x", ":443", ".evil", "%00", "%2fadmin", "//double",
    "/../escape", "\u2215unicode-slash", "\nheader: x", "\r\nX: y", "@evil.invalid",
    "?amount=999", ";param=x", "?redirect=https://evil.invalid",
])
def test_destination_edge_mutations_are_bound(suffix):
    c, _, _, _, authority, eff, sink = make_stack()
    cap = authority.authorize(c)
    mutated = replace(c, destination=c.destination + suffix)
    with pytest.raises(VerificationFailed):
        sink.effectuate(mutated, cap)
    assert not eff.records
