package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	canon "example.invalid/finality-interop/internal/canonical"
)

func sha(v any) string {
	h, err := canon.SHA256(v)
	if err != nil {
		panic(err)
	}
	return h
}
func mac(v any, key []byte) string {
	h, err := canon.HMACSHA256(v, key)
	if err != nil {
		panic(err)
	}
	return h
}
func obj(v any) map[string]any { return v.(map[string]any) }
func arr(v any) []any          { return v.([]any) }
func s(v any) string           { return v.(string) }
func num(v any) int64 {
	n := v.(json.Number)
	i, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil {
		panic(err)
	}
	return i
}
func eq(a, b, msg string) {
	if a != b {
		panic(fmt.Sprintf("%s: %s != %s", msg, a, b))
	}
}
func unsigned(m map[string]any) map[string]any {
	r := map[string]any{}
	for k, v := range m {
		if k != "signature" {
			r[k] = v
		}
	}
	return r
}
func without(m map[string]any, key string) map[string]any {
	r := map[string]any{}
	for k, v := range m {
		if k != key {
			r[k] = v
		}
	}
	return r
}

func main() {
	path := "../vectors/finality_case.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var d map[string]any
	if err := dec.Decode(&d); err != nil {
		panic(err)
	}
	key, err := hex.DecodeString(s(d["authority_key_hex"]))
	if err != nil {
		panic(err)
	}
	c := obj(d["candidate"])
	h := obj(d["hcad"])
	t := obj(d["state_transition"])
	e := obj(d["validation_evidence"])
	cap := obj(d["capability"])
	ctx := obj(d["sink_context"])
	if s(c["status"]) != "NON_EFFECTIVE" {
		panic("candidate not non-effective")
	}
	cd := sha(c)
	eq(cd, s(cap["candidate_digest"]), "candidate/cap")
	eq(cd, s(e["candidate_digest"]), "candidate/evidence")
	pd := sha(c["payload"])
	eq(pd, s(h["payload_digest"]), "payload digest")
	rebuilt := map[string]any{
		"schema": "finality-hcad/v1", "act_id": c["act_id"], "act_class": c["act_class"], "effect_class": c["effect_class"], "source": c["source"],
		"destination": c["destination"], "purpose": c["purpose"], "jurisdiction": c["jurisdiction"], "policy_epoch": c["policy_epoch"], "nonce": c["nonce"],
		"issued_at_ns": c["issued_at_ns"], "freshness_ns": c["freshness_ns"], "sink_id": ctx["sink_id"], "boundary_id": ctx["boundary_id"],
		"scope": c["scope"], "payload_digest": pd, "runtime_evidence_digest": c["runtime_evidence_digest"],
	}
	dd := sha(rebuilt)
	eq(dd, s(cap["descriptor_digest"]), "descriptor/cap")
	eq(dd, s(e["descriptor_digest"]), "descriptor/evidence")
	eq(sha(h), dd, "provided HCAD")
	tc := map[string]any{"nonce": t["nonce"], "source": t["source"], "before_version": t["before_version"], "after_version": t["after_version"], "quota_before": t["quota_before"], "quota_after": t["quota_after"], "budget_before": t["budget_before"], "budget_after": t["budget_after"], "policy_epoch": t["policy_epoch"], "candidate_digest": cd}
	eq(sha(tc), s(t["transition_id"]), "transition id")
	if num(t["after_version"]) != num(t["before_version"])+1 || num(t["quota_after"]) != num(t["quota_before"])-1 || num(t["budget_after"]) >= num(t["budget_before"]) {
		panic("invalid transition")
	}
	eq(s(t["transition_id"]), s(cap["transition_id"]), "transition cap")
	eq(s(t["transition_id"]), s(e["transition_id"]), "transition evidence")
	eu := unsigned(e)
	eq(mac(eu, key), s(e["signature"]), "evidence HMAC")
	eq(sha(without(eu, "evidence_id")), s(e["evidence_id"]), "evidence id")
	if s(e["decision"]) != "ALLOW" {
		panic("evidence not ALLOW")
	}
	cu := unsigned(cap)
	eq(mac(cu, key), s(cap["signature"]), "cap HMAC")
	eq(sha(without(cu, "capability_id")), s(cap["capability_id"]), "cap id")
	eq(s(cap["sink_id"]), s(ctx["sink_id"]), "sink")
	eq(s(cap["boundary_id"]), s(ctx["boundary_id"]), "boundary")
	if num(cap["policy_epoch"]) != num(ctx["policy_epoch"]) {
		panic("epoch mismatch")
	}
	eq(s(cap["nonce"]), s(c["nonce"]), "nonce")
	eq(s(cap["authority_id"]), s(e["authority_id"]), "authority")
	cs := arr(cap["scope"])
	xs := arr(ctx["supported_scopes"])
	if len(cs) != len(arr(c["scope"])) {
		panic("scope length")
	}
	for i, v := range cs {
		if s(v) != s(arr(c["scope"])[i]) {
			panic("scope mismatch")
		}
		ok := false
		for _, x := range xs {
			if s(v) == s(x) {
				ok = true
			}
		}
		if !ok {
			panic("unsupported scope")
		}
	}
	eq(s(c["effect_class"]), s(ctx["effect_class"]), "effect class")
	if num(cap["expires_at_ns"]) > num(c["issued_at_ns"])+num(c["freshness_ns"]) {
		panic("cap outlives candidate")
	}
	fmt.Println("Go portable Finality Sink verification: PASS")
}
