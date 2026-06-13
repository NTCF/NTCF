package ntcf

import (
	"fmt"
	"io"
	"time"

	"github.com/ntcf/ntcf/internal/column"
	"github.com/ntcf/ntcf/internal/compress"
	"github.com/ntcf/ntcf/internal/format"
	"github.com/ntcf/ntcf/internal/index"
	"github.com/ntcf/ntcf/internal/schema"
	"github.com/ntcf/ntcf/internal/util"
	"github.com/ntcf/ntcf/pkg/version"
)

// WriterOptions configures a Writer. Use DefaultWriterOptions and override.
type WriterOptions struct {
	// Compression selects the entropy codec applied after semantic encoding.
	Compression Compression
	// ZstdLevel is the zstd level (1 fastest .. 4 best) when Compression is zstd.
	ZstdLevel int
	// SegmentRows is the row count at which a segment is flushed. Smaller values
	// give finer index granularity and lower write-buffer memory; larger values
	// improve compression ratio. 65536 is a good default.
	SegmentRows int
	// SourceType records the originating telemetry source (e.g. "honeypot").
	SourceType string
	// BuildInverted additionally stores Roaring inverted indexes for indexed
	// columns. This speeds point lookups and top() to index-only operations at
	// the cost of larger files; by default only Bloom filters and zone maps are
	// written and equality predicates fall back to a single-column scan of
	// surviving segments.
	BuildInverted bool
	// WriterID is an opaque 16-byte producer identifier stored in the header.
	WriterID [16]byte
}

// DefaultWriterOptions returns sensible defaults: zstd level 3, 64K-row segments.
func DefaultWriterOptions() *WriterOptions {
	return &WriterOptions{
		Compression: CompressionZstd,
		ZstdLevel:   3,
		SegmentRows: 65536,
	}
}

// Writer encodes records into the NTCF container. It is not safe for concurrent
// use; serialise Append calls (the streaming ingester owns a single Writer).
type Writer struct {
	w        io.Writer
	schema   *schema.Schema
	opts     WriterOptions
	codec    compress.Codec
	builders []*column.Builder
	tsCol    int // index of the timestamp column, or -1

	pos       uint64
	segments  []format.SegmentDir
	totalRows uint64
	minTS     int64
	maxTS     int64
	haveTS    bool
	dirty     bool // rows added since the last footer was written
	closed    bool
}

// NewWriter validates the schema, writes the file header, and returns a Writer
// ready to accept records.
func NewWriter(w io.Writer, sch *Schema, opts *WriterOptions) (*Writer, error) {
	if sch == nil {
		return nil, fmt.Errorf("%w: nil schema", util.ErrSchema)
	}
	if err := sch.Validate(); err != nil {
		return nil, err
	}
	o := DefaultWriterOptions()
	if opts != nil {
		*o = *opts
	}
	if o.SegmentRows <= 0 {
		o.SegmentRows = 65536
	}
	if o.SegmentRows > util.MaxSegmentRows {
		o.SegmentRows = util.MaxSegmentRows
	}

	var codec compress.Codec
	var err error
	switch o.Compression {
	case CompressionZstd:
		codec, err = compress.NewZstd(o.ZstdLevel)
	default:
		codec, err = compress.Get(o.Compression)
	}
	if err != nil {
		return nil, err
	}

	wr := &Writer{
		w:      w,
		schema: sch,
		opts:   *o,
		codec:  codec,
		tsCol:  -1,
	}
	wr.builders = make([]*column.Builder, len(sch.Columns))
	for i, c := range sch.Columns {
		wr.builders[i] = column.NewBuilder(c.Type.Kind())
		if c.Type == schema.TypeTimestamp && wr.tsCol < 0 {
			wr.tsCol = i
		}
	}

	hdr := &format.Header{
		Version:  version.Format,
		Created:  time.Now().UnixNano(),
		WriterID: o.WriterID,
	}
	if err := wr.write(hdr.Append(nil)); err != nil {
		return nil, err
	}
	return wr, nil
}

func (w *Writer) write(p []byte) error {
	n, err := w.w.Write(p)
	w.pos += uint64(n)
	return err
}

// Append adds one record. The record must have exactly one value per schema
// column, in column order.
func (w *Writer) Append(rec Record) error {
	if w.closed {
		return fmt.Errorf("ntcf: append after close")
	}
	if len(rec) != len(w.schema.Columns) {
		return fmt.Errorf("%w: record has %d values, schema has %d columns", util.ErrSchema, len(rec), len(w.schema.Columns))
	}
	for j := range rec {
		b := w.builders[j]
		v := rec[j]
		switch {
		case v.Null:
			b.AppendNull()
		case w.schema.Columns[j].Type.Kind() == column.KindInt:
			b.AppendInt(v.Int)
		default:
			b.AppendBytes(v.Bytes)
		}
	}
	w.dirty = true
	if w.builders[0].Rows() >= w.opts.SegmentRows {
		return w.flushSegment()
	}
	return nil
}

// Flush forces the current in-progress segment to be written. It is a no-op if
// no rows are buffered.
func (w *Writer) Flush() error { return w.flushSegment() }

// Checkpoint flushes the current segment and appends an intermediate footer, so
// that a crash after this point leaves a fully valid, readable file containing
// every record written so far. The streaming ingester calls it periodically.
//
// Intermediate footers are appended (not overwritten), leaving the previous
// footer intact until the next is fully written — the property that makes
// recovery crash-safe. The trailing dead footers are skipped on normal reads
// (the final footer's offsets account for them) and are reclaimed by a future
// compaction pass (see docs/Roadmap.md). Checkpoint is a no-op if no rows were
// added since the last footer.
func (w *Writer) Checkpoint() error {
	if w.closed || !w.dirty {
		return nil
	}
	if err := w.flushSegment(); err != nil {
		return err
	}
	return w.writeFooter()
}

func (w *Writer) writeFooter() error {
	footer := &format.Footer{
		Schema:     w.schema,
		SourceType: w.opts.SourceType,
		TotalRows:  w.totalRows,
		MinTS:      w.minTS,
		MaxTS:      w.maxTS,
		Segments:   w.segments,
	}
	if err := w.write(footer.Append(nil)); err != nil {
		return err
	}
	w.dirty = false
	return nil
}

func (w *Writer) flushSegment() error {
	rows := w.builders[0].Rows()
	if rows == 0 {
		return nil
	}
	segStart := w.pos
	seg := format.SegmentDir{
		Offset:  segStart,
		Rows:    uint64(rows),
		Columns: make([]format.ColumnDir, len(w.builders)),
	}

	for j, b := range w.builders {
		st := b.Stats()
		col := &w.schema.Columns[j]
		cd := &seg.Columns[j]
		cd.HasNulls = st.HasNulls
		cd.NonNull = uint64(st.NonNull)
		if col.Type.Kind() == column.KindInt {
			cd.MinInt, cd.MaxInt = st.MinInt, st.MaxInt
		} else {
			cd.MinBytes, cd.MaxBytes = st.MinBytes, st.MaxBytes
		}

		chunk, _, err := b.Encode(w.codec)
		if err != nil {
			return err
		}
		cd.ChunkOffset = w.pos
		cd.ChunkLength = uint64(len(chunk))
		if err := w.write(chunk); err != nil {
			return err
		}

		if col.Indexed {
			var ci *index.ColumnIndex
			present := func(i int) bool { return b.Present(i) }
			if col.Type.Kind() == column.KindInt {
				ci = index.BuildIntColumn(b.Ints(), present, w.opts.BuildInverted)
			} else {
				ci = index.BuildBytesColumn(b.BytesVals(), present, w.opts.BuildInverted)
			}
			idxBytes := ci.Append(nil)
			cd.IndexOffset = w.pos
			cd.IndexLength = uint64(len(idxBytes))
			if err := w.write(idxBytes); err != nil {
				return err
			}
		}
	}

	seg.Length = w.pos - segStart
	if w.tsCol >= 0 {
		st := w.builders[w.tsCol].Stats()
		if st.NonNull > 0 {
			seg.MinTS = int64(st.MinInt)
			seg.MaxTS = int64(st.MaxInt)
			if !w.haveTS {
				w.minTS, w.maxTS, w.haveTS = seg.MinTS, seg.MaxTS, true
			} else {
				if seg.MinTS < w.minTS {
					w.minTS = seg.MinTS
				}
				if seg.MaxTS > w.maxTS {
					w.maxTS = seg.MaxTS
				}
			}
		}
	}
	w.totalRows += uint64(rows)
	w.segments = append(w.segments, seg)

	for _, b := range w.builders {
		b.Reset()
	}
	return nil
}

// Close flushes the final segment, writes the footer, and finalises the file.
// It does not close the underlying writer.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	if err := w.flushSegment(); err != nil {
		return err
	}
	if err := w.writeFooter(); err != nil {
		return err
	}
	w.closed = true
	return nil
}
