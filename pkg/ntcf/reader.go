package ntcf

import (
	"github.com/ntcf/ntcf/internal/store"
)

// Reader provides read access to an NTCF file: metadata, search, and queries.
type Reader struct {
	st *store.Reader
}

// Open opens an NTCF file by path.
func Open(path string) (*Reader, error) {
	st, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	return &Reader{st: st}, nil
}

// NewReader parses an in-memory NTCF file image.
func NewReader(data []byte) (*Reader, error) {
	st, err := store.New(data)
	if err != nil {
		return nil, err
	}
	return &Reader{st: st}, nil
}

// Close releases reader resources. (Currently a no-op; reserved for the
// memory-mapped reader.)
func (r *Reader) Close() error { return nil }

// Schema returns the file's schema.
func (r *Reader) Schema() *Schema { return r.st.Schema() }

// ColumnInfo summarises one column for Info.
type ColumnInfo struct {
	Name    string
	Type    string
	Indexed bool
}

// SegmentInfo summarises one segment for Info.
type SegmentInfo struct {
	Rows  uint64
	Bytes uint64
	MinTS int64
	MaxTS int64
}

// Info is a human-oriented summary of a file, backing `ntcf info`.
type Info struct {
	FormatVersion uint16
	SourceType    string
	SchemaName    string
	SchemaID      uint32
	TotalRows     uint64
	FileSize      int64
	MinTS         int64
	MaxTS         int64
	Columns       []ColumnInfo
	Segments      []SegmentInfo
}

// Info returns a summary of the file's metadata.
func (r *Reader) Info() Info {
	f := r.st.Footer()
	sch := f.Schema
	info := Info{
		FormatVersion: r.st.Header().Version,
		SourceType:    f.SourceType,
		SchemaName:    sch.Name,
		SchemaID:      sch.ID,
		TotalRows:     f.TotalRows,
		FileSize:      int64(r.st.Size()),
		MinTS:         f.MinTS,
		MaxTS:         f.MaxTS,
	}
	for _, c := range sch.Columns {
		info.Columns = append(info.Columns, ColumnInfo{Name: c.Name, Type: c.Type.String(), Indexed: c.Indexed})
	}
	for i := range f.Segments {
		seg := &f.Segments[i]
		info.Segments = append(info.Segments, SegmentInfo{
			Rows:  seg.Rows,
			Bytes: seg.Length,
			MinTS: seg.MinTS,
			MaxTS: seg.MaxTS,
		})
	}
	return info
}

// store exposes the low-level reader to sibling files in this package (writer
// tests, query/search). It is intentionally unexported.
func (r *Reader) store() *store.Reader { return r.st }
