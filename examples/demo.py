from __future__ import annotations
import time
from finality_ref import *

now=time.time_ns()
authn=HMACAuthenticator(b"demo-only-key")
evidence=EvidenceStore(authn)
state=ProtectedState()
policy=Policy(
    policy_epoch=1, allowed_purposes=frozenset({"demo"}), allowed_jurisdictions=frozenset({"EU"}),
    allowed_sinks=frozenset({"sink-1"}), allowed_boundaries=frozenset({"egress-1"}),
    allowed_effect_classes=frozenset({"network-egress"}), allowed_scopes=frozenset({"SEND"}),
    required_runtime_evidence_digest="attested-runtime-demo",
)
candidate=CandidateAct(
    act_id="demo-1",act_class="api-call",effect_class="network-egress",source="agent-1",
    destination="https://example.invalid/action",purpose="demo",jurisdiction="EU",policy_epoch=1,
    nonce="nonce-demo-1",issued_at_ns=now,freshness_ns=5_000_000_000,sink_id="sink-1",
    boundary_id="egress-1",scope=("SEND",),payload={"command":"hello"},
    runtime_evidence_digest="attested-runtime-demo",
)
authority=ProtectedAuthority(authority_id="authority-1",policy=policy,state=state,evidence_store=evidence,authenticator=authn)
effector=NetworkEffector()
sink=FinalitySink(
    context=SinkContext("sink-1","egress-1",1,frozenset({"SEND"}),"network-egress"),
    authenticator=authn,evidence_store=evidence,protected_state=state,
    consumption_store=InMemoryConsumptionStore(),effect_handle=effector.bind_for_sink(),
)
cap=authority.authorize(candidate)
print("candidate status before sink:", candidate.status.value)
print("capability:", cap.capability_id)
receipt=sink.effectuate(candidate,cap)
print("sink receipt:", receipt.receipt_id, receipt.effect_status)
print("external records:", len(effector.records))
