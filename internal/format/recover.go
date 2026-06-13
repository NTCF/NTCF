package format

import (
	"encoding/binary"

	"github.com/ntcf/ntcf/internal/util"
)

// RecoverFooter reconstructs the most recent valid footer from a possibly
// truncated file, e.g. one whose writer crashed mid-segment so the final footer
// was never written. It scans backwards for the footer trailer magic and
// returns the first (latest) candidate whose length and CRC validate.
//
// This works because the writer appends intermediate footers via Checkpoint
// without overwriting earlier ones: the last fully-flushed footer is always
// intact somewhere before the truncation point. Records written after that
// checkpoint but before the crash are not recovered (they were never committed
// to a footer), which is the correct durability boundary.
func RecoverFooter(file []byte) (*Footer, error) {
	n := len(file)
	minEnd := HeaderSize + footerTrailer
	// Walk candidate trailer-magic positions from the end toward the start.
	for end := n; end >= minEnd; end-- {
		if file[end-4] != Magic[0] || file[end-3] != Magic[1] ||
			file[end-2] != Magic[2] || file[end-1] != Magic[3] {
			continue
		}
		// Treat bytes up to `end` as a complete file and try to parse its footer.
		if f, err := tryFooterAt(file, end); err == nil {
			return f, nil
		}
	}
	return nil, util.ErrCorrupt
}

// tryFooterAt parses a footer whose trailer magic ends at offset end.
func tryFooterAt(file []byte, end int) (*Footer, error) {
	if end < HeaderSize+footerTrailer {
		return nil, util.ErrTruncated
	}
	bodyLen := binary.LittleEndian.Uint32(file[end-12 : end-8])
	if uint64(bodyLen) > util.MaxFooterSize {
		return nil, util.ErrLimitExceeded
	}
	bodyEnd := end - footerTrailer
	if int(bodyLen) > bodyEnd-HeaderSize {
		return nil, util.ErrCorrupt
	}
	// ReadFooter operates on a complete file image; slice off any trailing
	// bytes after this candidate so its trailer is at the very end.
	return ReadFooter(file[:end])
}
