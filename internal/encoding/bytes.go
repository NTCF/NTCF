package encoding

import (
	"encoding/binary"
	"sort"

	"github.com/ntcf/ntcf/internal/util"
)

// EncodeBytesAuto encodes vals with the byte-domain codec that yields the
// smallest pre-entropy payload. Dictionary encoding dominates for the
// low-cardinality string columns that pervade telemetry (event types, HTTP
// methods, country codes, normalised IPs); Raw is the always-available
// fallback for high-cardinality free text, which the entropy layer then
// handles.
func EncodeBytesAuto(vals [][]byte) (ID, []byte) {
	if len(vals) == 0 {
		return Raw, encodeRaw(vals)
	}
	st := analyzeBytes(vals)

	best := encodeRaw(vals)
	bestID := Raw
	consider := func(id ID, b []byte) {
		if b != nil && len(b) < len(best) {
			best, bestID = b, id
		}
	}
	if st.runs*3 < st.n {
		consider(RLEBytes, encodeRLEBytes(vals))
	}
	if st.distinct > 0 && st.distinct <= util.MaxDictEntries && st.distinct*4 < st.n*3 {
		consider(DictBytes, encodeDictBytes(vals, st.distinct))
	}
	return bestID, best
}

type bytesStats struct {
	n        int
	distinct int
	runs     int
}

func analyzeBytes(vals [][]byte) bytesStats {
	st := bytesStats{n: len(vals), runs: 1}
	seen := make(map[string]struct{}, min(len(vals), dictProbeLimit))
	capped := false
	for i, v := range vals {
		if i > 0 && string(v) != string(vals[i-1]) {
			st.runs++
		}
		if !capped {
			if _, ok := seen[string(v)]; !ok {
				if len(seen) >= dictProbeLimit {
					capped = true
				} else {
					seen[string(v)] = struct{}{}
				}
			}
		}
	}
	if capped {
		st.distinct = dictProbeLimit + 1 // signal "too many for dict"
	} else {
		st.distinct = len(seen)
	}
	return st
}

// --- Raw -------------------------------------------------------------------

func encodeRaw(vals [][]byte) []byte {
	out := make([]byte, 0, len(vals)*4)
	for _, v := range vals {
		out = binary.AppendUvarint(out, uint64(len(v)))
		out = append(out, v...)
	}
	return out
}

func decodeRaw(data []byte, n int) ([][]byte, error) {
	out := make([][]byte, n)
	pos := 0
	for i := 0; i < n; i++ {
		l, m := binary.Uvarint(data[pos:])
		if m <= 0 {
			return nil, errTruncated
		}
		pos += m
		if l > util.MaxBytesValue {
			return nil, errLimit
		}
		if pos+int(l) > len(data) {
			return nil, errTruncated
		}
		v := make([]byte, l)
		copy(v, data[pos:pos+int(l)])
		out[i] = v
		pos += int(l)
	}
	return out, nil
}

// --- Dictionary (bytes) ----------------------------------------------------

func encodeDictBytes(vals [][]byte, distinct int) []byte {
	keys := make([]string, 0, distinct)
	seen := make(map[string]uint32, distinct)
	for _, v := range vals {
		if _, ok := seen[string(v)]; !ok {
			seen[string(v)] = 0
			keys = append(keys, string(v))
		}
	}
	sort.Strings(keys)
	for i, k := range keys {
		seen[k] = uint32(i)
	}

	out := binary.AppendUvarint(make([]byte, 0, len(vals)), uint64(len(keys)))
	for _, k := range keys {
		out = binary.AppendUvarint(out, uint64(len(k)))
		out = append(out, k...)
	}
	idx := make([]uint64, len(vals))
	for i, v := range vals {
		idx[i] = uint64(seen[string(v)])
	}
	width := minWidth(uint64(len(keys) - 1))
	out = append(out, byte(width))
	return appendPacked(out, idx, width)
}

func decodeDictBytes(data []byte, n int) ([][]byte, error) {
	dictLen, m := binary.Uvarint(data)
	if m <= 0 {
		return nil, errTruncated
	}
	if err := util.CheckCount("dict", dictLen, util.MaxDictEntries); err != nil {
		return nil, err
	}
	pos := m
	dict := make([][]byte, dictLen)
	var total uint64
	for i := range dict {
		l, m := binary.Uvarint(data[pos:])
		if m <= 0 {
			return nil, errTruncated
		}
		pos += m
		if l > util.MaxBytesValue {
			return nil, errLimit
		}
		total += l
		if total > util.MaxStringTableBytes {
			return nil, errLimit
		}
		if pos+int(l) > len(data) {
			return nil, errTruncated
		}
		v := make([]byte, l)
		copy(v, data[pos:pos+int(l)])
		dict[i] = v
		pos += int(l)
	}
	if pos >= len(data) {
		if n == 0 {
			return [][]byte{}, nil
		}
		return nil, errTruncated
	}
	width := uint(data[pos])
	pos++
	if width > 64 {
		return nil, errBadWidth
	}
	idx := make([]uint64, n)
	if err := unpackInto(idx, data[pos:], width); err != nil {
		return nil, err
	}
	out := make([][]byte, n)
	for i, ix := range idx {
		if ix >= dictLen {
			return nil, errCorrupt
		}
		out[i] = dict[ix]
	}
	return out, nil
}

// --- Run-length (bytes) ----------------------------------------------------

func encodeRLEBytes(vals [][]byte) []byte {
	out := make([]byte, 0, 32)
	i := 0
	for i < len(vals) {
		j := i + 1
		for j < len(vals) && string(vals[j]) == string(vals[i]) {
			j++
		}
		out = binary.AppendUvarint(out, uint64(len(vals[i])))
		out = append(out, vals[i]...)
		out = binary.AppendUvarint(out, uint64(j-i))
		i = j
	}
	return out
}

func decodeRLEBytes(data []byte, n int) ([][]byte, error) {
	out := make([][]byte, 0, n)
	pos := 0
	for len(out) < n {
		l, m := binary.Uvarint(data[pos:])
		if m <= 0 {
			return nil, errTruncated
		}
		pos += m
		if l > util.MaxBytesValue {
			return nil, errLimit
		}
		if pos+int(l) > len(data) {
			return nil, errTruncated
		}
		val := make([]byte, l)
		copy(val, data[pos:pos+int(l)])
		pos += int(l)
		run, m := binary.Uvarint(data[pos:])
		if m <= 0 {
			return nil, errTruncated
		}
		pos += m
		if run == 0 || len(out)+int(run) > n {
			return nil, errCorrupt
		}
		for k := uint64(0); k < run; k++ {
			out = append(out, val)
		}
	}
	if len(out) != n {
		return nil, errCorrupt
	}
	return out, nil
}
