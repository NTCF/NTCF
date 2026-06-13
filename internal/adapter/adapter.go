// Package adapter converts raw telemetry from a given source into NTCF records
// against a canonical schema. Adapters are the extension point that lets NTCF
// understand new data sources without touching the storage engine: each adapter
// owns a schema and a Decode method, and registers itself by name.
//
// Three reference adapters ship in this build — generic-flow (the backbone
// schema most sources map onto), honeypot (SSH/RDP/etc. attack events), and
// web-access (nginx/apache/IIS access logs) — demonstrating both JSON-lines and
// text-line ingestion. Additional sources (Suricata eve, syslog, NetFlow, ...)
// are added as new adapters; see docs/Roadmap.md.
package adapter

import (
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/ntcf/ntcf/internal/row"
	"github.com/ntcf/ntcf/internal/schema"
	"github.com/ntcf/ntcf/internal/util"
)

// ErrSkip tells the ingester to drop a line without treating it as an error
// (e.g. blank lines, comments, or records that don't match the source).
var ErrSkip = errors.New("ntcf: skip record")

// Adapter decodes one source's records into NTCF rows.
type Adapter interface {
	// Name is the stable source identifier used on the command line.
	Name() string
	// Schema returns the canonical schema this adapter targets.
	Schema() *schema.Schema
	// Decode parses one input record (a line, for line-oriented sources).
	Decode(line []byte) (row.Record, error)
}

var registry = map[string]func() Adapter{}

// Register makes an adapter constructor available by name. Called from adapter
// package init functions.
func Register(name string, ctor func() Adapter) { registry[name] = ctor }

// Get returns a fresh adapter instance for name.
func Get(name string) (Adapter, bool) {
	ctor, ok := registry[name]
	if !ok {
		return nil, false
	}
	return ctor(), true
}

// Names returns the sorted list of registered adapter names.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// --- shared parsing helpers ------------------------------------------------

// asString returns the first present string-valued key, JSON-coercing numbers
// and bools to their textual form.
func asString(m map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			return t, true
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64), true
		case bool:
			return strconv.FormatBool(t), true
		}
	}
	return "", false
}

// asUint returns the first present numeric/string-numeric key as a uint64.
func asUint(m map[string]any, keys ...string) (uint64, bool) {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case float64:
			if t < 0 {
				return 0, false
			}
			return uint64(t), true
		case string:
			if n, err := strconv.ParseUint(t, 10, 64); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// parseTimeNanos converts a timestamp string to unix nanoseconds. It accepts
// RFC3339(/Nano) text and bare epoch integers, inferring the epoch unit from
// magnitude (seconds, millis, micros, or nanos).
func parseTimeNanos(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UnixNano(), true
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return epochToNanos(n), true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return epochToNanos(int64(f)), true
	}
	return 0, false
}

// epochToNanos normalises an integer epoch to nanoseconds by magnitude.
func epochToNanos(n int64) int64 {
	switch {
	case n < 1e11: // seconds (until year ~5138)
		return n * int64(time.Second)
	case n < 1e14: // milliseconds
		return n * int64(time.Millisecond)
	case n < 1e17: // microseconds
		return n * int64(time.Microsecond)
	default: // nanoseconds
		return n
	}
}

// --- value builders (map missing/invalid fields to null) -------------------

// ipValue returns a normalised 16-byte IP value, or null if absent/invalid.
func ipValue(m map[string]any, keys ...string) row.Value {
	if s, ok := asString(m, keys...); ok {
		if b, ok := util.NormalizeIP(s); ok {
			return row.BytesVal(b)
		}
	}
	return row.NullVal()
}

// strValue returns a byte value for the first present key, or null.
func strValue(m map[string]any, keys ...string) row.Value {
	if s, ok := asString(m, keys...); ok {
		return row.BytesVal([]byte(s))
	}
	return row.NullVal()
}

// uintValue returns an integer value for the first present key, or null.
func uintValue(m map[string]any, keys ...string) row.Value {
	if v, ok := asUint(m, keys...); ok {
		return row.IntVal(v)
	}
	return row.NullVal()
}

// enumValue wraps an already-extracted optional string.
func enumValue(s string, ok bool) row.Value {
	if !ok {
		return row.NullVal()
	}
	return row.BytesVal([]byte(s))
}

// upperCountry normalises a country code to uppercase ASCII (ISO-3166 alpha-2).
func upperCountry(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}
