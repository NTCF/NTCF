package query

import "testing"

func TestParseSelectForms(t *testing.T) {
	cases := []string{
		"SELECT count(*) FROM events",
		"SELECT count(*) FROM events WHERE country='RU'",
		"select top(asn) from events",
		"SELECT top(asn, 5) FROM events WHERE dstport = 22",
		"SELECT * FROM events LIMIT 10",
		"SELECT srcip, dstport FROM events WHERE asn = 15169 AND country = 'CN'",
		"SELECT * FROM events WHERE dstport IN (22, 23, 3389) OR country='RU'",
		"SELECT count(*) FROM events WHERE (asn=1 OR asn=2) AND dstport=22",
	}
	for _, q := range cases {
		if _, err := Parse(q); err != nil {
			t.Errorf("Parse(%q) failed: %v", q, err)
		}
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"",
		"SELECT",
		"SELECT count(*)",       // missing FROM
		"SELECT foo(x) FROM e",  // unknown func is parsed as projection then fails on '('
		"SELECT * FROM e WHERE", // dangling WHERE
		"SELECT * FROM e WHERE x =",
		"SELECT * FROM e LIMIT abc",
		"SELECT count(*) FROM e WHERE x = 'unterminated",
	}
	for _, q := range bad {
		if _, err := Parse(q); err == nil {
			t.Errorf("Parse(%q) expected error", q)
		}
	}
}

func TestParseWhereShape(t *testing.T) {
	st, err := Parse("SELECT * FROM events WHERE a=1 AND b=2 OR c=3")
	if err != nil {
		t.Fatal(err)
	}
	// Precedence: OR binds looser, so root is Or{ And{a,b}, c }.
	or, ok := st.Where.(Or)
	if !ok {
		t.Fatalf("root not Or: %T", st.Where)
	}
	if _, ok := or.L.(And); !ok {
		t.Fatalf("Or.L not And: %T", or.L)
	}
	if cmp, ok := or.R.(Cmp); !ok || cmp.Col != "c" {
		t.Fatalf("Or.R not Cmp(c): %+v", or.R)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("SELECT count(*) FROM events WHERE country='RU'")
	f.Add("SELECT top(asn,5) FROM events")
	f.Fuzz(func(t *testing.T, q string) {
		_, _ = Parse(q) // must never panic
	})
}
