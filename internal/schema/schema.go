// Package schema defines NTCF's logical column types and the self-describing
// schema descriptor embedded in every file footer.
//
// A logical type carries telemetry semantics (this column is an IP, an ASN, a
// port, an event-type enum, a timestamp) which determine: the physical value
// domain (integer vs bytes), how raw input is normalised into that domain, and
// which codecs and indexes are sensible. Because the resolved descriptor is
// written into the footer, an .ntcf file is readable with no external schema
// registry — the registry exists only so adapters and the CLI can refer to
// named schemas like "generic-flow".
package schema

import (
	"encoding/binary"
	"fmt"

	"github.com/ntcf/ntcf/internal/column"
	"github.com/ntcf/ntcf/internal/util"
)

// LogicalType is the semantic type of a column. Values are stable on disk.
type LogicalType uint8

const (
	TypeTimestamp LogicalType = 0 // unix nanoseconds, integer domain, delta-of-delta friendly
	TypeIP        LogicalType = 1 // IPv4/IPv6 normalised to 16 bytes, bytes domain
	TypeUint      LogicalType = 2 // generic unsigned (ASN, counters, ids), integer domain
	TypePort      LogicalType = 3 // transport port 0..65535, integer domain
	TypeEnum      LogicalType = 4 // low-cardinality string (eventtype, method, country), bytes domain
	TypeString    LogicalType = 5 // possibly high-cardinality string (url, user-agent), bytes domain
	TypeBool      LogicalType = 6 // boolean stored as 0/1, integer domain
)

func (t LogicalType) String() string {
	switch t {
	case TypeTimestamp:
		return "timestamp"
	case TypeIP:
		return "ip"
	case TypeUint:
		return "uint"
	case TypePort:
		return "port"
	case TypeEnum:
		return "enum"
	case TypeString:
		return "string"
	case TypeBool:
		return "bool"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(t))
	}
}

// Kind returns the physical value domain backing this logical type.
func (t LogicalType) Kind() column.Kind {
	switch t {
	case TypeIP, TypeEnum, TypeString:
		return column.KindBytes
	default:
		return column.KindInt
	}
}

func (t LogicalType) valid() bool { return t <= TypeBool }

// Column is one column definition.
type Column struct {
	Name     string      `json:"name"`
	Type     LogicalType `json:"type"`
	Indexed  bool        `json:"indexed"`  // build bloom/bitmap indexes for fast search
	Nullable bool        `json:"nullable"` // may contain nulls
}

// Schema is an ordered set of columns with an identity.
type Schema struct {
	ID      uint32   `json:"id"`
	Name    string   `json:"name"`
	Version uint16   `json:"version"`
	Columns []Column `json:"columns"`
}

// Index returns the column index for name, or -1.
func (s *Schema) Index(name string) int {
	for i := range s.Columns {
		if s.Columns[i].Name == name {
			return i
		}
	}
	return -1
}

// Validate checks structural constraints (bounded size, unique names, known
// types). It is called on read before any data is interpreted.
func (s *Schema) Validate() error {
	if len(s.Columns) == 0 {
		return fmt.Errorf("%w: schema %q has no columns", util.ErrSchema, s.Name)
	}
	if len(s.Columns) > util.MaxColumns {
		return fmt.Errorf("%w: %d columns exceeds %d", util.ErrSchema, len(s.Columns), util.MaxColumns)
	}
	seen := make(map[string]struct{}, len(s.Columns))
	for _, c := range s.Columns {
		if c.Name == "" {
			return fmt.Errorf("%w: empty column name", util.ErrSchema)
		}
		if !c.Type.valid() {
			return fmt.Errorf("%w: column %q has unknown type %d", util.ErrSchema, c.Name, uint8(c.Type))
		}
		if _, dup := seen[c.Name]; dup {
			return fmt.Errorf("%w: duplicate column %q", util.ErrSchema, c.Name)
		}
		seen[c.Name] = struct{}{}
	}
	return nil
}

// AppendDescriptor serialises the schema into the footer descriptor format.
func (s *Schema) AppendDescriptor(dst []byte) []byte {
	dst = binary.LittleEndian.AppendUint32(dst, s.ID)
	dst = binary.AppendUvarint(dst, uint64(len(s.Name)))
	dst = append(dst, s.Name...)
	dst = binary.LittleEndian.AppendUint16(dst, s.Version)
	dst = binary.AppendUvarint(dst, uint64(len(s.Columns)))
	for _, c := range s.Columns {
		dst = binary.AppendUvarint(dst, uint64(len(c.Name)))
		dst = append(dst, c.Name...)
		dst = append(dst, byte(c.Type))
		var flags byte
		if c.Indexed {
			flags |= 1
		}
		if c.Nullable {
			flags |= 2
		}
		dst = append(dst, flags)
	}
	return dst
}

// ReadDescriptor parses a schema descriptor from a bounds-checked cursor.
func ReadDescriptor(c *util.Cursor) (*Schema, error) {
	s := &Schema{}
	s.ID = c.U32()
	nameLen := c.Uvarint()
	if err := util.CheckCount("schema name", nameLen, 4096); err != nil {
		return nil, err
	}
	s.Name = string(c.Bytes(int(nameLen)))
	s.Version = c.U16()
	colCount := c.Uvarint()
	if err := util.CheckCount("columns", colCount, util.MaxColumns); err != nil {
		return nil, err
	}
	s.Columns = make([]Column, colCount)
	for i := range s.Columns {
		nl := c.Uvarint()
		if err := util.CheckCount("column name", nl, 4096); err != nil {
			return nil, err
		}
		s.Columns[i].Name = string(c.Bytes(int(nl)))
		s.Columns[i].Type = LogicalType(c.U8())
		flags := c.U8()
		s.Columns[i].Indexed = flags&1 != 0
		s.Columns[i].Nullable = flags&2 != 0
	}
	if c.Err() != nil {
		return nil, c.Err()
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}
