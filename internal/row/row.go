// Package row defines the neutral record type exchanged between ingestion
// adapters and the writer. It lives in its own low-level package so that
// adapters and the public pkg/ntcf API can both depend on it without creating
// an import cycle.
package row

// Value is one column's value within a record. For integer-domain columns Int
// is meaningful; for byte-domain columns Bytes is. Null marks a missing value
// regardless of domain.
type Value struct {
	Null  bool
	Int   uint64
	Bytes []byte
}

// IntVal builds a present integer value.
func IntVal(v uint64) Value { return Value{Int: v} }

// BytesVal builds a present byte value.
func BytesVal(b []byte) Value { return Value{Bytes: b} }

// NullVal builds a null value.
func NullVal() Value { return Value{Null: true} }

// Record is one row: one Value per schema column, in column order.
type Record []Value
