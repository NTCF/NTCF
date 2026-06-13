// Package format defines the NTCF container framing: the fixed file header, the
// footer (schema descriptor + segment/column directory + file statistics), and
// the routines that read them back with full bounds and checksum validation.
//
// On-disk shape of a complete file:
//
//	[Header]                         fixed-size, CRC32C-protected
//	[Segment 0][Segment 1]...        opaque concatenation of column chunks +
//	                                 index blobs (offsets recorded in footer)
//	[Footer body]                    schema + per-segment/per-column directory
//	[footerLen u32][CRC32C u32]['NTCF']
//
// The footer is read first (seek to end) for fast open and zone-map pruning;
// each segment is also self-describing enough for crash recovery when the
// footer is missing (see internal/ingest recovery).
package format

import (
	"encoding/binary"

	"github.com/ntcf/ntcf/internal/util"
	"github.com/ntcf/ntcf/pkg/version"
)

// Magic marks both the start of the header and the end of the footer.
var Magic = [4]byte{'N', 'T', 'C', 'F'}

// HeaderSize is the fixed encoded size of a file header.
//
//	magic(4) + version(2) + flags(2) + created(8) + writerID(16) + crc(4)
const HeaderSize = 4 + 2 + 2 + 8 + 16 + 4

// Header flag bits (reserved for future format-level options).
const (
	FlagReserved uint16 = 0
)

// Header is the fixed file header.
type Header struct {
	Version  uint16
	Flags    uint16
	Created  int64 // unix nanoseconds at file creation
	WriterID [16]byte
}

// Append encodes the header (including its trailing CRC32C) to dst.
func (h *Header) Append(dst []byte) []byte {
	start := len(dst)
	dst = append(dst, Magic[:]...)
	dst = binary.LittleEndian.AppendUint16(dst, h.Version)
	dst = binary.LittleEndian.AppendUint16(dst, h.Flags)
	dst = binary.LittleEndian.AppendUint64(dst, uint64(h.Created))
	dst = append(dst, h.WriterID[:]...)
	crc := util.CRC32C(dst[start:])
	dst = binary.LittleEndian.AppendUint32(dst, crc)
	return dst
}

// ReadHeader parses and validates a header from the first HeaderSize bytes of
// buf: magic, supported version, and CRC32C integrity.
func ReadHeader(buf []byte) (*Header, error) {
	if len(buf) < HeaderSize {
		return nil, util.ErrTruncated
	}
	body := buf[:HeaderSize-4]
	wantCRC := binary.LittleEndian.Uint32(buf[HeaderSize-4 : HeaderSize])
	if util.CRC32C(body) != wantCRC {
		return nil, util.ErrChecksum
	}
	c := util.NewCursor(body)
	c.Magic(Magic[:])
	h := &Header{}
	h.Version = c.U16()
	h.Flags = c.U16()
	h.Created = int64(c.U64())
	copy(h.WriterID[:], c.Bytes(16))
	if c.Err() != nil {
		return nil, c.Err()
	}
	if !version.SupportsFormat(h.Version) {
		return nil, util.ErrUnsupportedVersion
	}
	return h, nil
}
