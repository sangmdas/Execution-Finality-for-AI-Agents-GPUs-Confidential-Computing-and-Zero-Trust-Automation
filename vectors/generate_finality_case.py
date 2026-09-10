from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from finality_ref.authority import ProtectedAuthority
from finality_ref.crypto import HMACAuthenticator
from finality_ref.evidence import EvidenceStore
from finality_ref.models import CandidateAct, build_hcad
from finality_ref.policy import Policy
from finality_ref.state import ProtectedState

NOW = 1_700_000_000_000_000  # below Number.MAX_SAFE_INTEGER for portable vectors
KEY = b"portable-finality-authority-key"


def build_case(*, filename: str, act_id: str, nonce: str, purpose: str, destination: str, payload: dict, authority_context: dict):
    authn = HMACAuthenticator(KEY, key_id="portable-authority-v1")
    evstore = EvidenceStore(authn)
    state = ProtectedState(default_quota=10, default_budget=100)
    policy = Policy(
        policy_epoch=7,
        allowed_purposes=frozenset({purpose}),
        allowed_jurisdictions=frozenset({"EU"}),
        allowed_sinks=frozenset({"sink-portable"}),
        allowed_boundaries=frozenset({"boundary-portable"}),
        allowed_effect_classes=frozenset({"payment-ledger"}),
        allowed_scopes=frozenset({"SETTLE"}),
        required_runtime_evidence_digest="runtime-portable",
    )
    c = CandidateAct(
        act_id=act_id,
        act_class="payment",
        effect_class="payment-ledger",
        source="agent-portable",
        destination=destination,
        purpose=purpose,
        jurisdiction="EU",
        policy_epoch=7,
        nonce=nonce,
        issued_at_ns=NOW,
        freshness_ns=5_000_000_000,
        sink_id="sink-portable",
        boundary_id="boundary-portable",
        scope=("SETTLE",),
        payload=payload,
        runtime_evidence_digest="runtime-portable",
        authority_context=authority_context,
    )
    a = ProtectedAuthority(
        authority_id="portable-authority",
        policy=policy,
        state=state,
        evidence_store=evstore,
        authenticator=authn,
        capability_ttl_ns=2_000_000_000,
        clock=lambda: NOW,
    )
    cap = a.authorize(c, now_ns=NOW)
    ev = evstore.get(cap.evidence_id)
    t = state.get_transition(cap.transition_id)
    hcad = build_hcad(c, sink_id="sink-portable", boundary_id="boundary-portable")
    assert ev is not None and t is not None
    bundle = {
        "schema": "portable-execution-finality-case/v1",
        "authority_key_hex": KEY.hex(),
        "sink_context": {
            "sink_id": "sink-portable",
            "boundary_id": "boundary-portable",
            "policy_epoch": 7,
            "supported_scopes": ["SETTLE"],
            "effect_class": "payment-ledger",
        },
        "candidate": asdict(c),
        "hcad": asdict(hcad),
        "state_transition": asdict(t),
        "validation_evidence": asdict(ev),
        "capability": asdict(cap),
    }
    (ROOT / 'vectors' / filename).write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding='utf-8')


build_case(
    filename="finality_case.json",
    act_id="portable-act-1",
    nonce="portable-nonce-1",
    purpose="settlement-demo",
    destination="ledger://demo/beneficiary-B1",
    payload={"amount_minor": 12345, "currency": "EUR", "beneficiary": "B1"},
    authority_context={"runtime": "portable-demo"},
)

# Deliberately use decomposed Unicode in several load-bearing Candidate fields.
# Python signs the NFC-canonical representation; independent Node and Go sinks
# must normalize the raw decomposed JSON input to reproduce the same digests.
build_case(
    filename="finality_case_unicode.json",
    act_id="portable-act-unicode-1",
    nonce="portable-nonce-unicode-1",
    purpose="settlement-cafe\u0301",
    destination="ledger://demo/beneficiary-Jose\u0301",
    payload={"amount_minor": 54321, "currency": "EUR", "beneficiary": "Jose\u0301", "memo": "re\u0301sume\u0301"},
    authority_context={"runtime": "portable-demo", "label": "cafe\u0301"},
)

print('wrote portable finality cases (baseline + decomposed Unicode)')
