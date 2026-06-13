package format

import (
	"encoding/binary"

	"github.com/ntcf/ntcf/internal/column"
	"github.com/ntcf/ntcf/internal/schema"
	"github.com/ntcf/ntcf/internal/util"
)

// ColumnDir locates a column's chunk and optional index within the file and
// carries its zone-map statistics so a search can prune the segment without
// touching the segment body.
type ColumnDir struct {
	ChunkOffset uint64
	ChunkLength uint64
	IndexOffset uint64 // 0 means no index blob for this column
	IndexLength uint64

	HasNulls bool
	NonNull  uint64

	// Zone-map min/max over present values. Interpreted per the column's
	// logical kind (integer vs bytes), known from the schema.
	MinInt, MaxInt     uint64
	MinBytes, MaxBytes []byte
}

// SegmentDir describes one segment (row group): where it lives, how many rows
// it holds, its timestamp span (for time-range pruning), and its columns.
type SegmentDir struct {
	Offset  uint64
	Length  uint64
	Rows    uint64
	MinTS   int64
	MaxTS   int64
	Columns []ColumnDir
}

// Footer is the file's metadata roll-up.
type Footer struct {
	Schema     *schema.Schema
	SourceType string
	TotalRows  uint64
	MinTS      int64
	MaxTS      int64
	Segments   []SegmentDir
}

// trailer overhead after the footer body: footerLen(4) + crc(4) + magic(4).
const footerTrailer = 4 + 4 + 4

// Append encodes the complete footer (body + length + CRC + trailer magic).
func (f *Footer) Append(dst []byte) []byte {
	bodyStart := len(dst)
	dst = f.Schema.AppendDescriptor(dst)
	dst = binary.AppendUvarint(dst, uint64(len(f.SourceType)))
	dst = append(dst, f.SourceType...)
	dst = binary.LittleEndian.AppendUint64(dst, f.TotalRows)
	dst = binary.LittleEndian.AppendUint64(dst, uint64(f.MinTS))
	dst = binary.LittleEndian.AppendUint64(dst, uint64(f.MaxTS))
	dst = binary.AppendUvarint(dst, uint64(len(f.Segments)))
	for i := range f.Segments {
		seg := &f.Segments[i]
		dst = binary.LittleEndian.AppendUint64(dst, seg.Offset)
		dst = binary.LittleEndian.AppendUint64(dst, seg.Length)
		dst = binary.AppendUvarint(dst, seg.Rows)
		dst = binary.LittleEndian.AppendUint64(dst, uint64(seg.MinTS))
		dst = binary.LittleEndian.AppendUint64(dst, uint64(seg.MaxTS))
		dst = binary.AppendUvarint(dst, uint64(len(seg.Columns)))
		for j := range seg.Columns {
			col := &seg.Columns[j]
			dst = binary.LittleEndian.AppendUint64(dst, col.ChunkOffset)
			dst = binary.LittleEndian.AppendUint64(dst, col.ChunkLength)
			dst = binary.LittleEndian.AppendUint64(dst, col.IndexOffset)
			dst = binary.LittleEndian.AppendUint64(dst, col.IndexLength)
			var flags byte
			if col.HasNulls {
				flags |= 1
			}
			dst = append(dst, flags)
			dst = binary.AppendUvarint(dst, col.NonNull)
			if f.Schema.Columns[j].Type.Kind() == column.KindInt {
				dst = binary.LittleEndian.AppendUint64(dst, col.MinInt)
				dst = binary.LittleEndian.AppendUint64(dst, col.MaxInt)
			} else {
				dst = binary.AppendUvarint(dst, uint64(len(col.MinBytes)))
				dst = append(dst, col.MinBytes...)
				dst = binary.AppendUvarint(dst, uint64(len(col.MaxBytes)))
				dst = append(dst, col.MaxBytes...)
			}
		}
	}
	bodyLen := len(dst) - bodyStart
	crc := util.CRC32C(dst[bodyStart:])
	dst = binary.LittleEndian.AppendUint32(dst, uint32(bodyLen))
	dst = binary.LittleEndian.AppendUint32(dst, crc)
	dst = append(dst, Magic[:]...)
	return dst
}

// ReadFooter locates and parses the footer given the whole file's trailing
// bytes. fileSize is the total file length; tail must contain at least the
// footer region (callers typically pass the entire file or a sufficient
// suffix; here we pass the full mapped/loaded file for simplicity).
func ReadFooter(file []byte) (*Footer, error) {
	n := len(file)
	if n < HeaderSize+footerTrailer {
		return nil, util.ErrTruncated
	}
	if [4]byte(file[n-4:n]) != Magic {
		return nil, util.ErrBadMagic
	}
	bodyLen := binary.LittleEndian.Uint32(file[n-12 : n-8])
	wantCRC := binary.LittleEndian.Uint32(file[n-8 : n-4])
	if err := util.CheckCount("footer", uint64(bodyLen), util.MaxFooterSize); err != nil {
		return nil, err
	}
	bodyEnd := n - footerTrailer
	if int(bodyLen) > bodyEnd-HeaderSize {
		return nil, util.ErrCorrupt
	}
	body := file[bodyEnd-int(bodyLen) : bodyEnd]
	if util.CRC32C(body) != wantCRC {
		return nil, util.ErrChecksum
	}

	c := util.NewCursor(body)
	sch, err := schema.ReadDescriptor(c)
	if err != nil {
		return nil, err
	}
	f := &Footer{Schema: sch}
	stLen := c.Uvarint()
	if err := util.CheckCount("source type", stLen, 4096); err != nil {
		return nil, err
	}
	f.SourceType = string(c.Bytes(int(stLen)))
	f.TotalRows = c.U64()
	f.MinTS = int64(c.U64())
	f.MaxTS = int64(c.U64())
	segCount := c.Uvarint()
	if err := util.CheckCount("segments", segCount, util.MaxSegments); err != nil {
		return nil, err
	}
	if c.Err() != nil {
		return nil, c.Err()
	}
	f.Segments = make([]SegmentDir, segCount)
	for i := range f.Segments {
		seg := &f.Segments[i]
		seg.Offset = c.U64()
		seg.Length = c.U64()
		seg.Rows = c.Uvarint()
		seg.MinTS = int64(c.U64())
		seg.MaxTS = int64(c.U64())
		colCount := c.Uvarint()
		if colCount != uint64(len(sch.Columns)) {
			return nil, util.ErrCorrupt
		}
		seg.Columns = make([]ColumnDir, colCount)
		for j := range seg.Columns {
			col := &seg.Columns[j]
			col.ChunkOffset = c.U64()
			col.ChunkLength = c.U64()
			col.IndexOffset = c.U64()
			col.IndexLength = c.U64()
			flags := c.U8()
			col.HasNulls = flags&1 != 0
			col.NonNull = c.Uvarint()
			if sch.Columns[j].Type.Kind() == column.KindInt {
				col.MinInt = c.U64()
				col.MaxInt = c.U64()
			} else {
				ml := c.Uvarint()
				if err := util.CheckCount("min bytes", ml, util.MaxBytesValue); err != nil {
					return nil, err
				}
				col.MinBytes = append([]byte(nil), c.Bytes(int(ml))...)
				xl := c.Uvarint()
				if err := util.CheckCount("max bytes", xl, util.MaxBytesValue); err != nil {
					return nil, err
				}
				col.MaxBytes = append([]byte(nil), c.Bytes(int(xl))...)
			}
		}
	}
	if c.Err() != nil {
		return nil, c.Err()
	}
	return f, nil
}
