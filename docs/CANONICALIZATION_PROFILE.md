# Cross-Language Canonicalization Profile

## Why this profile exists

An act-bound capability is only meaningful if every verifier computes the same bytes for the same security-bound structure. A Python producer and a Go or Node Finality Sink must not disagree because of Unicode normalization, key ordering, floating-point formatting, JSON escaping, or numeric precision.

The repository therefore distinguishes two profiles:

1. **Python local canonicalization** — used internally by the complete Python reference. It supports arbitrary Python integers and an explicit tagged representation for Python `bytes`.
2. **Portable cross-language canonicalization** — used by the Python/Go/Node interoperability vectors and portable Finality Sink case. It intentionally accepts a narrower data domain.

## Portable data domain

The portable profile permits:

- `null` / `None`;
- booleans;
- integers from `-(2^53-1)` through `+(2^53-1)`;
- Unicode scalar-value strings (unpaired UTF-16 surrogate code points are forbidden);
- arrays/lists containing portable values;
- objects/maps with string keys and portable values.

The portable profile rejects:

- floating-point values, including NaN and infinities;
- integers outside the JavaScript-safe integer range;
- binary byte strings as a native type;
- non-string object keys;
- key collisions that appear after Unicode normalization;
- unsupported application-specific runtime types.

The canonicalizer operates on typed values, not on arbitrary JSON lexical spellings. Vector JSON is only a transport for the test corpus. A production protocol must separately define parsing rules if inputs can arrive as arbitrary JSON text (for example exponent-form numbers or duplicate lexical keys).

The safe-integer restriction is deliberate. It prevents Node.js from silently rounding an integer that Python or Go would otherwise represent exactly. Nanosecond timestamps used by a portable vector must therefore be chosen within this exact range or represented using a different, normatively specified representation.

## Unicode normalization

All string values are normalized to **Unicode NFC** before serialization.

All object keys are also NFC-normalized **before** collision detection and sorting.

For example, the precomposed key `é` and the decomposed key `e + COMBINING ACUTE ACCENT` normalize to the same key. An object containing both is rejected instead of allowing one value to overwrite the other.

The Go implementation uses the vendored `golang.org/x/text/unicode/norm` package. This fixes the earlier weak form in which Go happened to agree only when inputs had already been normalized. Python and Node also reject unpaired surrogate code points rather than allowing runtime-specific handling to define the security bytes.

## Key ordering

After NFC normalization, object keys are ordered lexically by Unicode scalar value / valid UTF-8 byte order.

This is explicitly implemented in Node using UTF-8 byte comparison rather than relying on JavaScript's default UTF-16 code-unit sort. The distinction matters for some supplementary-plane characters. The interoperability vectors contain a deliberate BMP-versus-emoji ordering case to detect this class of error.

## JSON string representation

The resulting structure is encoded as compact UTF-8 JSON:

- no insignificant whitespace;
- object keys in the canonical order above;
- non-control Unicode emitted directly as UTF-8 rather than ASCII-only `\uXXXX` escaping;
- quote and backslash escaped;
- standard JSON short escapes used for backspace, form feed, newline, carriage return and tab;
- other U+0000–U+001F controls encoded with lowercase four-digit `\u00xx` form.

The Go implementation contains its own narrow string encoder because Go's default `encoding/json` HTML/JSONP escaping rules can differ from Python `ensure_ascii=False` and modern JavaScript `JSON.stringify` for some characters.

## Unicode data-version note

The recorded runtimes do not all ship the same Unicode data version: Python 3.13.5 reports Unicode 15.1.0, the tested Node.js 22.16.0 reports Unicode 16.0, and Go 1.23.2 reports Unicode 15.0.0 while the vendored `x/text` package is v0.16.0. The included vectors use long-established normalization behavior and pass identically in all three runtimes.

This repository therefore claims conformance to the **included profile vectors and tested repertoire**, not an exhaustive proof over every code point introduced by every Unicode version. A standards-track deployment that accepts unrestricted Unicode should pin a normalization-data version/repertoire or adopt a canonical encoding implementation with the same normative Unicode tables across all endpoints.

## Interoperability conformance material

`vectors/interop.json` contains **20 positive deterministic vectors** that bind:

`canonical UTF-8 bytes -> SHA-256 -> HMAC-SHA256`.

The additional hardening vectors include:

- decomposed Unicode string input;
- decomposed Unicode object key input;
- supplementary-plane versus BMP key ordering;
- `<`, `>`, `&`, U+2028, U+2029 and JSON control escaping;
- canonically equivalent Angstrom/ring forms.

`vectors/canonicalization_conformance.json` contains **9 focused cases**: five positive cases and four rejection cases. Rejection cases include an NFC key collision, a floating-point value, and positive/negative integers beyond the safe portable range.

Python, Node.js and Go independently execute these conformance cases.

## Non-claim

This profile is a deliberately narrow engineering profile for the runnable reference. It is not presented as a new universal JSON standard. A standards-track deployment should either normatively specify every serialization rule with formal test vectors or adopt an established canonical encoding that meets the system's requirements.
