package adapter

import (
	"testing"

	"github.com/ntcf/ntcf/internal/util"
)

func TestRegistry(t *testing.T) {
	for _, name := range []string{"generic-flow", "honeypot", "web-access"} {
		a, ok := Get(name)
		if !ok {
			t.Fatalf("adapter %q not registered", name)
		}
		if err := a.Schema().Validate(); err != nil {
			t.Fatalf("%s schema invalid: %v", name, err)
		}
	}
}

func TestGenericFlowDecode(t *testing.T) {
	a, _ := Get("generic-flow")
	line := []byte(`{"timestamp":"2024-03-01T12:00:00Z","srcip":"203.0.113.5","dstip":"198.51.100.9","srcport":54321,"dstport":443,"protocol":"tcp","asn":15169,"country":"us","eventtype":"flow","bytes":1500,"packets":3}`)
	rec, err := a.Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	sch := a.Schema()
	if len(rec) != len(sch.Columns) {
		t.Fatalf("record arity %d != %d", len(rec), len(sch.Columns))
	}
	want, _ := util.NormalizeIP("203.0.113.5")
	if string(rec[sch.Index("srcip")].Bytes) != string(want) {
		t.Error("srcip mismatch")
	}
	if rec[sch.Index("dstport")].Int != 443 {
		t.Error("dstport mismatch")
	}
	if string(rec[sch.Index("country")].Bytes) != "US" {
		t.Errorf("country should be uppercased, got %q", rec[sch.Index("country")].Bytes)
	}
}

func TestHoneypotNullUsername(t *testing.T) {
	a, _ := Get("honeypot")
	line := []byte(`{"timestamp":"2024-03-01T12:00:00Z","srcip":"45.61.0.7","dstport":22,"protocol":"ssh","eventtype":"login.failed","asn":13335}`)
	rec, err := a.Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	sch := a.Schema()
	if !rec[sch.Index("username")].Null {
		t.Error("username should be null when absent")
	}
	if string(rec[sch.Index("protocol")].Bytes) != "ssh" {
		t.Error("protocol mismatch")
	}
}

func TestWebAccessCombined(t *testing.T) {
	a, _ := Get("web-access")
	line := []byte(`192.0.2.10 - - [01/Mar/2024:12:00:00 +0000] "GET /admin/login HTTP/1.1" 401 512 "http://example.com/" "Mozilla/5.0"`)
	rec, err := a.Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	sch := a.Schema()
	if string(rec[sch.Index("method")].Bytes) != "GET" {
		t.Errorf("method=%q", rec[sch.Index("method")].Bytes)
	}
	if string(rec[sch.Index("path")].Bytes) != "/admin/login" {
		t.Errorf("path=%q", rec[sch.Index("path")].Bytes)
	}
	if rec[sch.Index("status")].Int != 401 {
		t.Errorf("status=%d", rec[sch.Index("status")].Int)
	}
	if string(rec[sch.Index("useragent")].Bytes) != "Mozilla/5.0" {
		t.Errorf("ua=%q", rec[sch.Index("useragent")].Bytes)
	}
}

func FuzzAdaptersDecode(f *testing.F) {
	f.Add([]byte(`{"timestamp":"2024-03-01T12:00:00Z","srcip":"1.2.3.4"}`))
	f.Add([]byte(`1.2.3.4 - - [01/Mar/2024:12:00:00 +0000] "GET / HTTP/1.1" 200 1`))
	f.Fuzz(func(t *testing.T, line []byte) {
		for _, name := range Names() {
			a, _ := Get(name)
			_, _ = a.Decode(line) // must never panic
		}
	})
}
