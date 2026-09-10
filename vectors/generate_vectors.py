from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from finality_ref.canonical import portable_canonical_bytes

KEY = b"interop-reference-key-v1"
VALUES = [
    {"act":"send","amount":1000,"currency":"EUR"},
    {"scope":["SEND"],"sink":"sink-A","boundary":"b-A","nonce":"n-1"},
    {"nested":{"a":1,"b":2},"list":[1,2,3]},
    {"unicode":"café","purpose":"résumé"},
    {"unicode":"日本語","purpose":"test"},
    {"unicode":"हिन्दी","purpose":"test"},
    {"unicode":"العربية","purpose":"test"},
    {"emoji":"🔐","ok":True,"none":None},
    {"n":0,"neg":-1,"max_safe":9007199254740991},
    {"destination":"https://example.invalid/api","method":"POST"},
    {"effect_class":"storage-write","path":"/records/1","scope":["WRITE:/records"]},
    {"effect_class":"renderer","surface":"display-0","scope":["DISPLAY"]},
    {"policy_epoch":7,"runtime_evidence":"abc123","freshness_ns":5000000000},
    {"payload":{"beneficiary":"B1","amount_minor":1000},"purpose":"approved-purpose"},
    {"z":3,"m":2,"a":1,"nested":{"z":0,"a":9}},
    # Cross-language Unicode hardening vectors. These are intentionally not all NFC at input.
    {"unicode":"cafe\u0301","purpose":"re\u0301sume\u0301"},
    {"e\u0301":"cafe\u0301","plain":"ok"},
    {"😀":1,"\ue000":2,"A":3},  # catches UTF-16-vs-Unicode-scalar key ordering differences
    {"json":"<>&\u2028\u2029\b\u000b\\\""},
    {"marks":"A\u030a","angstrom":"Å","precomposed":"Å"},
]

vectors=[]
for i, value in enumerate(VALUES):
    cb=portable_canonical_bytes(value)
    vectors.append({
        "id": f"v{i+1:02d}",
        "value": value,
        "canonical_utf8": cb.decode("utf-8"),
        "sha256": hashlib.sha256(cb).hexdigest(),
        "hmac_sha256": hmac.new(KEY, cb, hashlib.sha256).hexdigest(),
    })
out={"schema":"finality-interop-v2","key_hex":KEY.hex(),"vectors":vectors}
(ROOT/"vectors"/"interop.json").write_text(json.dumps(out, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")

positive_values = [
    ("decomposed-string", {"v":"cafe\u0301"}),
    ("decomposed-key", {"e\u0301":"value"}),
    ("supplementary-key-order", {"😀":1,"\ue000":2,"A":3}),
    ("json-string-escaping", {"v":"<>&\u2028\u2029\b\u000b\\\""}),
    ("canonical-equivalence", {"angstrom":"Å","ring":"A\u030a","pre":"Å"}),
]
positive=[]
for ident, value in positive_values:
    positive.append({"id": ident, "value": value, "canonical_utf8": portable_canonical_bytes(value).decode("utf-8")})

# These values must be rejected by all three language implementations.
negative = [
    {"id":"nfc-key-collision", "value":{"é":1,"e\u0301":2}},
    {"id":"floating-point", "value":{"n":1.5}},
    {"id":"unsafe-positive-integer", "value":{"n":9007199254740992}},
    {"id":"unsafe-negative-integer", "value":{"n":-9007199254740992}},
]
conformance={"schema":"finality-canonicalization-conformance-v1","positive":positive,"negative":negative}
(ROOT/"vectors"/"canonicalization_conformance.json").write_text(json.dumps(conformance, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
print(f"wrote {len(vectors)} interop vectors and {len(positive)+len(negative)} canonicalization conformance cases")
