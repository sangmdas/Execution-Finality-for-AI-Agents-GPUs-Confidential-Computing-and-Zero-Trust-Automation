import fs from 'node:fs';
import { sha256 as sha, hmacSha256 as mac } from './canonical.mjs';

function eq(a,b,msg){if(a!==b) throw new Error(`${msg}: ${a} != ${b}`);}
function unsigned(obj){const x={...obj}; delete x.signature; return x;}

const path=process.argv[2] ?? '../vectors/finality_case.json';
const d=JSON.parse(fs.readFileSync(path,'utf8'));
const key=Buffer.from(d.authority_key_hex,'hex');
const c=d.candidate, h=d.hcad, t=d.state_transition, e=d.validation_evidence, cap=d.capability, ctx=d.sink_context;

if(c.status!=='NON_EFFECTIVE') throw new Error('candidate is not non-effective');
const candidateDigest=sha(c); eq(candidateDigest,cap.candidate_digest,'candidate digest/capability'); eq(candidateDigest,e.candidate_digest,'candidate digest/evidence');
const payloadDigest=sha(c.payload); eq(payloadDigest,h.payload_digest,'payload digest');
const rebuilt={
  schema:'finality-hcad/v1',act_id:c.act_id,act_class:c.act_class,effect_class:c.effect_class,source:c.source,
  destination:c.destination,purpose:c.purpose,jurisdiction:c.jurisdiction,policy_epoch:c.policy_epoch,nonce:c.nonce,
  issued_at_ns:c.issued_at_ns,freshness_ns:c.freshness_ns,sink_id:ctx.sink_id,boundary_id:ctx.boundary_id,
  scope:c.scope,payload_digest:payloadDigest,runtime_evidence_digest:c.runtime_evidence_digest
};
const descriptorDigest=sha(rebuilt); eq(descriptorDigest,cap.descriptor_digest,'descriptor digest/capability'); eq(descriptorDigest,e.descriptor_digest,'descriptor digest/evidence'); eq(sha(h),descriptorDigest,'provided HCAD');

const transitionCore={nonce:t.nonce,source:t.source,before_version:t.before_version,after_version:t.after_version,
  quota_before:t.quota_before,quota_after:t.quota_after,budget_before:t.budget_before,budget_after:t.budget_after,
  policy_epoch:t.policy_epoch,candidate_digest:candidateDigest};
eq(sha(transitionCore),t.transition_id,'transition id');
if(t.after_version!==t.before_version+1 || t.quota_after!==t.quota_before-1 || !(t.budget_after<t.budget_before)) throw new Error('invalid protected state transition');
eq(t.transition_id,cap.transition_id,'transition cap'); eq(t.transition_id,e.transition_id,'transition evidence');

const evidenceUnsigned=unsigned(e); eq(mac(evidenceUnsigned,key),e.signature,'evidence HMAC');
const evidenceCore={...evidenceUnsigned}; delete evidenceCore.evidence_id; eq(sha(evidenceCore),e.evidence_id,'evidence id');
if(e.decision!=='ALLOW') throw new Error('evidence is not ALLOW');

const capUnsigned=unsigned(cap); eq(mac(capUnsigned,key),cap.signature,'capability HMAC');
const capCore={...capUnsigned}; delete capCore.capability_id; eq(sha(capCore),cap.capability_id,'capability id');

eq(cap.sink_id,ctx.sink_id,'sink binding'); eq(cap.boundary_id,ctx.boundary_id,'boundary binding');
eq(cap.policy_epoch,ctx.policy_epoch,'policy epoch'); eq(cap.nonce,c.nonce,'nonce'); eq(cap.authority_id,e.authority_id,'authority');
if(cap.scope.length!==c.scope.length || !cap.scope.every((v,i)=>v===c.scope[i])) throw new Error('scope mismatch');
if(!cap.scope.every(s=>ctx.supported_scopes.includes(s))) throw new Error('sink unsupported scope');
if(c.effect_class!==ctx.effect_class) throw new Error('effect class mismatch');
if(cap.expires_at_ns>c.issued_at_ns+c.freshness_ns) throw new Error('capability outlives candidate');

console.log('Node portable Finality Sink verification: PASS');
