package index

import (
	"github.com/ntcf/ntcf/internal/util"
)

// Index blob flag bits.
const (
	flagBloom    = 1 << 0
	flagInverted = 1 << 1
)

// DefaultFPRate is the Bloom filter target false-positive rate. 1% trades a
// little space for strong cross-segment pruning.
const DefaultFPRate = 0.01

// ColumnIndex bundles the optional indexes for one indexed column of one
// segment. Either field may be nil; the search engine uses whatever exists.
type ColumnIndex struct {
	Bloom    *Bloom
	Inverted *Inverted
}

// bloomProbeCap bounds the distinct-value set used to size a Bloom filter; past
// it the filter is sized by row count instead. It also caps the work spent
// estimating cardinality.
const bloomProbeCap = 1 << 20

// BuildIntColumn constructs the indexes for an integer column. It always builds
// a Bloom filter sized to the column's distinct cardinality (not its row count,
// which would massively over-allocate for the low-cardinality columns typical
// of telemetry). An inverted index is built only when withInverted is set,
// because for dictionary-encoded columns the posting lists are reconstructable
// from the column itself — paying for them on disk is a deliberate, opt-in
// trade of size for the fastest possible point lookups and top() queries.
func BuildIntColumn(vals []uint64, present func(int) bool, withInverted bool) *ColumnIndex {
	distinct := make(map[uint64]struct{}, 64)
	capped := false
	for i, v := range vals {
		if present != nil && !present(i) {
			continue
		}
		if !capped {
			distinct[v] = struct{}{}
			if len(distinct) >= bloomProbeCap {
				capped = true
			}
		}
	}
	n := len(distinct)
	if capped {
		n = len(vals)
	}
	bl := NewBloom(n, DefaultFPRate)
	if capped {
		for i, v := range vals {
			if present == nil || present(i) {
				bl.AddU64(v)
			}
		}
	} else {
		for v := range distinct {
			bl.AddU64(v)
		}
	}
	ci := &ColumnIndex{Bloom: bl}
	if withInverted {
		ci.Inverted = BuildInvertedInts(vals, present)
	}
	return ci
}

// BuildBytesColumn constructs the indexes for a byte column (see BuildIntColumn).
func BuildBytesColumn(vals [][]byte, present func(int) bool, withInverted bool) *ColumnIndex {
	distinct := make(map[string]struct{}, 64)
	capped := false
	for i, v := range vals {
		if present != nil && !present(i) {
			continue
		}
		if !capped {
			distinct[string(v)] = struct{}{}
			if len(distinct) >= bloomProbeCap {
				capped = true
			}
		}
	}
	n := len(distinct)
	if capped {
		n = len(vals)
	}
	bl := NewBloom(n, DefaultFPRate)
	if capped {
		for i, v := range vals {
			if present == nil || present(i) {
				bl.Add(v)
			}
		}
	} else {
		for v := range distinct {
			bl.Add([]byte(v))
		}
	}
	ci := &ColumnIndex{Bloom: bl}
	if withInverted {
		ci.Inverted = BuildInvertedBytes(vals, present)
	}
	return ci
}

// Append serialises the column index blob.
func (ci *ColumnIndex) Append(dst []byte) []byte {
	var flags byte
	if ci.Bloom != nil {
		flags |= flagBloom
	}
	if ci.Inverted != nil {
		flags |= flagInverted
	}
	dst = append(dst, flags)
	if ci.Bloom != nil {
		dst = ci.Bloom.Append(dst)
	}
	if ci.Inverted != nil {
		dst = ci.Inverted.Append(dst)
	}
	return dst
}

// ReadColumnIndex parses a column index blob. An empty/zero-length blob decodes
// to an empty (no-op) index.
func ReadColumnIndex(raw []byte) (*ColumnIndex, error) {
	if len(raw) == 0 {
		return &ColumnIndex{}, nil
	}
	c := util.NewCursor(raw)
	flags := c.U8()
	if c.Err() != nil {
		return nil, c.Err()
	}
	ci := &ColumnIndex{}
	if flags&flagBloom != 0 {
		bl, err := ReadBloom(c)
		if err != nil {
			return nil, err
		}
		ci.Bloom = bl
	}
	if flags&flagInverted != 0 {
		iv, err := ReadInverted(c)
		if err != nil {
			return nil, err
		}
		ci.Inverted = iv
	}
	return ci, nil
}
