package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	canon "example.invalid/finality-interop/internal/canonical"
)

type Vector struct {
	ID        string `json:"id"`
	Value     any    `json:"value"`
	Canonical string `json:"canonical_utf8"`
	SHA       string `json:"sha256"`
	HMAC      string `json:"hmac_sha256"`
}
type Bundle struct {
	KeyHex  string   `json:"key_hex"`
	Vectors []Vector `json:"vectors"`
}

func main() {
	path := "../vectors/interop.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var bundle Bundle
	if err := dec.Decode(&bundle); err != nil {
		panic(err)
	}
	key, err := hex.DecodeString(bundle.KeyHex)
	if err != nil {
		panic(err)
	}
	ok := 0
	for _, v := range bundle.Vectors {
		c, err := canon.Canonical(v.Value)
		if err != nil {
			panic(fmt.Sprintf("%s canonicalization error: %v", v.ID, err))
		}
		if string(c) != v.Canonical {
			panic(fmt.Sprintf("%s canonical mismatch: %s != %s", v.ID, c, v.Canonical))
		}
		sh := sha256.Sum256(c)
		if hex.EncodeToString(sh[:]) != v.SHA {
			panic(v.ID + " sha mismatch")
		}
		m := hmac.New(sha256.New, key)
		_, _ = m.Write(c)
		if hex.EncodeToString(m.Sum(nil)) != v.HMAC {
			panic(v.ID + " hmac mismatch")
		}
		ok++
	}
	fmt.Printf("Go interop verified %d/%d vectors\n", ok, len(bundle.Vectors))
}
