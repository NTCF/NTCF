// Package store is the low-level read engine over an NTCF file image: it parses
// the header and footer, then provides bounds-checked access to individual
// column chunks and per-column indexes. Both the public pkg/ntcf reader and the
// internal query engine build on it, so segment/column access and validation
// live in exactly one place.
//
// The current implementation operates on the whole file held in memory. This
// still delivers NTCF's central promise — search and analytics without
// decompressing everything — because only the chunks that survive zone-map and
// bloom pruning are ever decoded. Memory-mapped and partial-IO readers are a
// documented roadmap item for very large files.
package store

import (
	"fmt"
	"os"

	"github.com/ntcf/ntcf/internal/column"
	"github.com/ntcf/ntcf/internal/format"
	"github.com/ntcf/ntcf/internal/index"
	"github.com/ntcf/ntcf/internal/schema"
	"github.com/ntcf/ntcf/internal/util"
)

// Reader provides validated access to an NTCF file image.
type Reader struct {
	data   []byte
	header *format.Header
	footer *format.Footer
}

// Open reads an entire file into memory and parses its metadata.
func Open(path string) (*Reader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return New(data)
}

// New parses an in-memory file image. The image is retained, not copied.
func New(data []byte) (*Reader, error) {
	hdr, err := format.ReadHeader(data)
	if err != nil {
		return nil, err
	}
	ftr, err := format.ReadFooter(data)
	if err != nil {
		return nil, err
	}
	return &Reader{data: data, header: hdr, footer: ftr}, nil
}

// Recover opens a file whose final footer is missing or corrupt (e.g. a writer
// crash) by scanning backwards for the most recent valid checkpoint footer. It
// returns the reader plus a bool indicating whether recovery was needed.
func Recover(data []byte) (*Reader, bool, error) {
	hdr, err := format.ReadHeader(data)
	if err != nil {
		return nil, false, err
	}
	if ftr, err := format.ReadFooter(data); err == nil {
		return &Reader{data: data, header: hdr, footer: ftr}, false, nil
	}
	ftr, err := format.RecoverFooter(data)
	if err != nil {
		return nil, false, err
	}
	return &Reader{data: data, header: hdr, footer: ftr}, true, nil
}

// Header returns the parsed file header.
func (r *Reader) Header() *format.Header { return r.header }

// Footer returns the parsed footer (schema + segment directory + stats).
func (r *Reader) Footer() *format.Footer { return r.footer }

// Schema returns the file's schema.
func (r *Reader) Schema() *schema.Schema { return r.footer.Schema }

// Size returns the file image size in bytes.
func (r *Reader) Size() int { return len(r.data) }

// slice returns data[off:off+length] after validating the range lies within the
// file, turning any corrupt offset/length in the footer into a clean error.
func (r *Reader) slice(off, length uint64) ([]byte, error) {
	end := off + length
	if end < off || end > uint64(len(r.data)) {
		return nil, fmt.Errorf("%w: chunk [%d,%d) outside file of %d", util.ErrCorrupt, off, end, len(r.data))
	}
	return r.data[off:end], nil
}

// Column decodes column colIdx of segment segIdx into a Data vector.
func (r *Reader) Column(segIdx, colIdx int) (*column.Data, error) {
	if segIdx < 0 || segIdx >= len(r.footer.Segments) {
		return nil, fmt.Errorf("%w: segment %d", util.ErrCorrupt, segIdx)
	}
	seg := &r.footer.Segments[segIdx]
	if colIdx < 0 || colIdx >= len(seg.Columns) {
		return nil, fmt.Errorf("%w: column %d", util.ErrCorrupt, colIdx)
	}
	cd := &seg.Columns[colIdx]
	raw, err := r.slice(cd.ChunkOffset, cd.ChunkLength)
	if err != nil {
		return nil, err
	}
	return column.DecodeChunk(raw)
}

// Index returns the parsed index blob for column colIdx of segment segIdx. If
// the column has no index, it returns an empty (no-op) ColumnIndex.
func (r *Reader) Index(segIdx, colIdx int) (*index.ColumnIndex, error) {
	seg := &r.footer.Segments[segIdx]
	cd := &seg.Columns[colIdx]
	if cd.IndexLength == 0 {
		return &index.ColumnIndex{}, nil
	}
	raw, err := r.slice(cd.IndexOffset, cd.IndexLength)
	if err != nil {
		return nil, err
	}
	return index.ReadColumnIndex(raw)
}
