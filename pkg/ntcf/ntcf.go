// Package ntcf is the public, stable API for reading and writing NTCF
// (Network & Telemetry Compression Format) files. SIEM vendors, pipelines, and
// other embedders should depend only on this package; everything under
// internal/ is implementation detail and may change between minor releases.
//
// Typical write:
//
//	w, _ := ntcf.NewWriter(f, sch, ntcf.DefaultWriterOptions())
//	for _, rec := range records { _ = w.Append(rec) }
//	_ = w.Close()
//
// Typical read:
//
//	r, _ := ntcf.Open("events.ntcf")
//	defer r.Close()
//	info := r.Info()
package ntcf

import (
	"github.com/ntcf/ntcf/internal/compress"
	"github.com/ntcf/ntcf/internal/row"
	"github.com/ntcf/ntcf/internal/schema"
	"github.com/ntcf/ntcf/internal/util"
)

// Re-exported core types so embedders need only this import.
type (
	// Schema describes the columns of an NTCF file.
	Schema = schema.Schema
	// Column is one column definition.
	Column = schema.Column
	// LogicalType is the semantic type of a column.
	LogicalType = schema.LogicalType
	// Value is a single column value within a Record.
	Value = row.Value
	// Record is one row of values in column order.
	Record = row.Record
	// Compression selects the entropy codec for a file.
	Compression = compress.ID
)

// Logical column types.
const (
	TypeTimestamp = schema.TypeTimestamp
	TypeIP        = schema.TypeIP
	TypeUint      = schema.TypeUint
	TypePort      = schema.TypePort
	TypeEnum      = schema.TypeEnum
	TypeString    = schema.TypeString
	TypeBool      = schema.TypeBool
)

// Entropy codecs.
const (
	CompressionNone = compress.None
	CompressionZstd = compress.Zstd
	CompressionLZ4  = compress.LZ4
)

// Value constructors re-exported for convenience.
var (
	IntVal   = row.IntVal
	BytesVal = row.BytesVal
	NullVal  = row.NullVal
)

// NormalizeIP parses a textual IPv4/IPv6 address into the canonical 16-byte form
// that TypeIP columns store (IPv4 as a v4-in-v6 mapped address). Use it to build
// Values for IP columns and to construct search terms so they match storage.
func NormalizeIP(s string) ([]byte, bool) { return util.NormalizeIP(s) }

// IPString renders a 16-byte normalized address (as stored in a TypeIP column)
// back to its textual form.
func IPString(b []byte) string { return util.IPString(b) }
