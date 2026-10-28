// Package ueu builds, canonicalises and protects Universal Evidence Utility
// envelopes as KEEN's profile defines them (docs/evidence-format.md).
package ueu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxSafeInteger bounds integers so every implementation reads them exactly.
const MaxSafeInteger = 1<<53 - 1

// ErrCanonical reports a value the KEEN profile cannot canonicalise.
var ErrCanonical = errors.New("UEU_CANONICALISATION_FAILED")

// Canonical returns RFC 8785 (JSON Canonicalization Scheme) bytes. The KEEN
// profile admits integers only, so numbers never need ECMAScript float
// formatting. Values may be built from Go maps, slices and scalars, or decoded
// with encoding/json using UseNumber.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, v, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any, depth int) error {
	if depth > 32 {
		return fmt.Errorf("%w: nesting exceeds 32 levels", ErrCanonical)
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		return writeString(b, x)
	case int:
		return writeInt(b, int64(x))
	case int64:
		return writeInt(b, x)
	case uint32:
		return writeInt(b, int64(x))
	case float64:
		if x != math.Trunc(x) || math.IsInf(x, 0) {
			return fmt.Errorf("%w: only integers are allowed", ErrCanonical)
		}
		return writeInt(b, int64(x))
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil {
			return fmt.Errorf("%w: only integers are allowed", ErrCanonical)
		}
		return writeInt(b, n)
	case []string:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeString(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, item, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			if !utf8.ValidString(k) {
				return fmt.Errorf("%w: invalid UTF-8 in a member name", ErrCanonical)
			}
			keys = append(keys, k)
		}
		// RFC 8785 orders members by their UTF-16 code units.
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := writeCanonical(b, x[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, s := range x {
			m[k] = s
		}
		return writeCanonical(b, m, depth)
	default:
		return fmt.Errorf("%w: unsupported value %T", ErrCanonical, v)
	}
	return nil
}

func writeInt(b *bytes.Buffer, n int64) error {
	if n > MaxSafeInteger || n < -MaxSafeInteger {
		return fmt.Errorf("%w: integer outside the exact range", ErrCanonical)
	}
	b.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func writeString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: invalid UTF-8", ErrCanonical)
	}
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

func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

// Decode parses JSON for canonicalisation, keeping integers exact.
func Decode(data []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errors.New("trailing JSON")
	}
	return v, nil
}
