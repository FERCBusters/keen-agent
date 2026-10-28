package ueu

import (
	"errors"
	"testing"
)

func TestCanonicalOrderingAndEscaping(t *testing.T) {
	// RFC 8785 section 3.2.3 sorts by UTF-16 code units, so U+1F600 (a
	// surrogate pair beginning 0xD83D) sorts before U+FB33 (0xFB33).
	v := map[string]any{
		"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh",
		"1": "One", "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control", "\u00f6": "Latin Small Letter O With Diaeresis",
	}
	b, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001f600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
	b, err = Canonical(map[string]any{"b": []any{true, nil, int64(-5)}, "a": "x\u0001\u001f\"\\\u007f\u2028"})
	if err != nil || string(b) != "{\"a\":\"x\\u0001\\u001f\\\"\\\\\u007f\u2028\",\"b\":[true,null,-5]}" {
		t.Fatalf("%s %v", b, err)
	}
}

func TestCanonicalRejectsWhatProfilesForbid(t *testing.T) {
	for _, v := range []any{1.5, int64(1 << 53), "\xff", map[string]any{"\xff": 1}, struct{}{}} {
		if _, err := Canonical(v); !errors.Is(err, ErrCanonical) {
			t.Fatalf("accepted %#v", v)
		}
	}
	deep := any("x")
	for i := 0; i < 40; i++ {
		deep = []any{deep}
	}
	if _, err := Canonical(deep); err == nil {
		t.Fatal("accepted deep nesting")
	}
}

func TestDecodeRoundTripIsStable(t *testing.T) {
	v, err := Decode([]byte(`{ "z": [1, 2, {"b": 9007199254740991, "a": "\u00e9"}], "a": false }`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Canonical(v)
	if err != nil || string(b) != `{"a":false,"z":[1,2,{"a":"é","b":9007199254740991}]}` {
		t.Fatalf("%s %v", b, err)
	}
	if _, err = Decode([]byte(`{} {}`)); err == nil {
		t.Fatal("accepted trailing JSON")
	}
}
