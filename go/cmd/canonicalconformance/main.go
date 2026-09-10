package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	canon "example.invalid/finality-interop/internal/canonical"
)

type Positive struct {
	ID        string `json:"id"`
	Value     any    `json:"value"`
	Canonical string `json:"canonical_utf8"`
}
type Negative struct {
	ID    string `json:"id"`
	Value any    `json:"value"`
}
type Cases struct {
	Positive []Positive `json:"positive"`
	Negative []Negative `json:"negative"`
}

func main() {
	path := "../vectors/canonicalization_conformance.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var cases Cases
	if err := dec.Decode(&cases); err != nil {
		panic(err)
	}
	passed := 0
	for _, tc := range cases.Positive {
		got, err := canon.Canonical(tc.Value)
		if err != nil {
			panic(fmt.Sprintf("%s unexpectedly rejected: %v", tc.ID, err))
		}
		if string(got) != tc.Canonical {
			panic(fmt.Sprintf("%s mismatch: %s != %s", tc.ID, got, tc.Canonical))
		}
		passed++
	}
	for _, tc := range cases.Negative {
		if got, err := canon.Canonical(tc.Value); err == nil {
			panic(fmt.Sprintf("%s unexpectedly accepted: %s", tc.ID, got))
		}
		passed++
	}
	fmt.Printf("Go canonicalization conformance verified %d/%d cases\n", passed, len(cases.Positive)+len(cases.Negative))
}
