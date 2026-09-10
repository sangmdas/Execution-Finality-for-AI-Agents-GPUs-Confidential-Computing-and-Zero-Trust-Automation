// Package canonical implements the narrow, cross-language canonical profile used
// by the execution-finality reference vectors. It is intentionally stricter
// than generic JSON: Unicode is NFC-normalized, map keys are normalized before
// sorting, collisions after normalization are rejected, floats are forbidden,
// and integers are restricted to the JavaScript-safe range so Python, Go and
// Node.js cannot silently disagree about numeric identity.
package canonical

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const MaxSafeInteger int64 = 9007199254740991 // 2^53 - 1

var maxSafeBig = big.NewInt(MaxSafeInteger)
var minSafeBig = big.NewInt(-MaxSafeInteger)

func validateInteger(n json.Number) error {
	s := n.String()
	z := new(big.Int)
	if _, ok := z.SetString(s, 10); !ok {
		return fmt.Errorf("non-integer number %s", s)
	}
	if z.Cmp(maxSafeBig) > 0 || z.Cmp(minSafeBig) < 0 {
		return fmt.Errorf("integer outside portable safe range: %s", s)
	}
	return nil
}

// appendJSONString emits the same narrow string form used by Python
// json.dumps(..., ensure_ascii=False) and modern JSON.stringify for Unicode
// scalar strings: printable/non-control Unicode is emitted as UTF-8, while JSON
// control characters, quote and backslash are escaped.
func appendJSONString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("invalid UTF-8 string")
	}
	s = norm.NFC.String(s)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}

// Canonical returns canonical UTF-8 bytes for a value decoded with
// json.Decoder.UseNumber().
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := appendCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func appendCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		if err := validateInteger(x); err != nil {
			return err
		}
		b.WriteString(x.String())
	case string:
		return appendJSONString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := appendCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		normalized := make(map[string]any, len(x))
		keys := make([]string, 0, len(x))
		for rawKey, val := range x {
			if !utf8.ValidString(rawKey) {
				return fmt.Errorf("invalid UTF-8 object key")
			}
			k := norm.NFC.String(rawKey)
			if _, exists := normalized[k]; exists {
				return fmt.Errorf("key collision after Unicode normalization: %q", k)
			}
			normalized[k] = val
			keys = append(keys, k)
		}
		// Go string ordering is UTF-8 byte lexical ordering for valid strings,
		// which is also Unicode scalar-value ordering and matches Python's
		// ordering for these normalized scalar strings.
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := appendJSONString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := appendCanonical(b, normalized[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported %T", v)
	}
	return nil
}

func SHA256(v any) (string, error) {
	c, err := Canonical(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(c)
	return hex.EncodeToString(h[:]), nil
}

func HMACSHA256(v any, key []byte) (string, error) {
	c, err := Canonical(v)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(c)
	return hex.EncodeToString(m.Sum(nil)), nil
}
