from __future__ import annotations
import time
from finality_ref import *

now=time.time_ns()
authority_key=HMACAuthenticator(b"authority-demo", key_id="authority-A")
presenter_key=HMACAuthenticator(b"presenter-demo", key_id="presenter-A")
sink_key=HMACAuthenticator(b"sink-receipt-demo", key_id="sink-A-receipt")
evidence=EvidenceStore(authority_key); state=ProtectedState(); eff=NetworkEffector()
policy=Policy(1,frozenset({"demo"}),frozenset({"EU"}),frozenset({"sink-A"}),frozenset({"boundary-A"}),
              frozenset({"network-egress"}),frozenset({"SEND"}),required_runtime_evidence_digest="runtime-ok")
c=CandidateAct("a1","api-call","network-egress","agent-A","https://example.invalid","demo","EU",1,"n1",now,
               5_000_000_000,"sink-A","boundary-A",("SEND",),{"x":1},"runtime-ok",{"presenter_key_id":"presenter-A"})
a=ProtectedAuthority(authority_id="authority-A",policy=policy,state=state,evidence_store=evidence,authenticator=authority_key)
s=FinalitySink(context=SinkContext("sink-A","boundary-A",1,frozenset({"SEND"}),"network-egress"),
               authenticator=authority_key,receipt_authenticator=sink_key,evidence_store=evidence,protected_state=state,
               consumption_store=InMemoryConsumptionStore(),effect_handle=eff.bind_for_sink(),
               presenter_verifier=PresenterVerifierRegistry({"presenter-A":presenter_key}),require_presentation_proof=True)
cap=a.authorize(c)
proof=Presenter(presenter_key).prove(capability_id=cap.capability_id,candidate_digest=c.digest(),sink_id=c.sink_id,
                                   boundary_id=c.boundary_id,nonce=c.nonce,presented_at_ns=time.time_ns())
receipt=s.effectuate(c,cap,presentation_proof=proof)
print(receipt.effect_status, receipt.key_id)
