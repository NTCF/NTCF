// Package compress is NTCF's generic entropy layer: the second compression
// stage that runs after a column's semantic codec (see internal/encoding).
// Where the semantic layer removes structural redundancy a byte compressor
// cannot see, this layer removes residual byte-level entropy.
//
// Three codecs are supported, selected per file:
//
//   - None: store the semantic payload verbatim (useful when it is already
//     near-incompressible, or for latency-sensitive ingestion).
//   - Zstd: high ratio, good speed (klauspost/compress, pure Go, no cgo).
//   - LZ4: maximum speed for hot ingestion (pierrec/lz4, pure Go).
//
// Every Decompress call takes the exact expected output length (carried in the
// column-chunk header) so that (a) LZ4's block API can pre-size its buffer and
// (b) the result length can be validated, turning a corrupt length field into
// an error rather than a silent truncation. Decompression-bomb ceilings are
// enforced by the caller via util.CheckDecompress before this layer is invoked,
// and reinforced here by the zstd decoder's bounded max-memory setting.
package compress

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
	"github.com/ntcf/ntcf/internal/util"
	"github.com/pierrec/lz4/v4"
)

// ID identifies the entropy codec used for a column chunk. Stable on disk.
type ID uint8

const (
	None ID = 0
	Zstd ID = 1
	LZ4  ID = 2
)

// String returns the codec name for ntcf info / debugging.
func (id ID) String() string {
	switch id {
	case None:
		return "none"
	case Zstd:
		return "zstd"
	case LZ4:
		return "lz4"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(id))
	}
}

// Codec compresses and decompresses a single column-chunk payload.
type Codec interface {
	ID() ID
	// Compress returns the compressed form of src. Implementations guarantee
	// the result is self-describing enough to be inverted by Decompress given
	// the original length.
	Compress(src []byte) []byte
	// Decompress inverts Compress. outLen is the exact expected size of the
	// decompressed output; an implementation returns an error if the data does
	// not produce exactly outLen bytes.
	Decompress(src []byte, outLen int) ([]byte, error)
}

// shared, goroutine-safe zstd encoder/decoder for the default level and for all
// decoding. The decoder caps memory to bound decompression bombs even if a
// caller forgets to pre-validate.
var (
	zstdDecoder *zstd.Decoder
)

func init() {
	d, err := zstd.NewReader(nil,
		zstd.WithDecoderMaxMemory(util.MaxChunkUncompressed),
		zstd.WithDecoderConcurrency(1),
	)
	if err != nil {
		panic("ntcf: zstd decoder init: " + err.Error())
	}
	zstdDecoder = d
}

// Get returns a decode-capable codec for id at the default encode level. For
// custom zstd levels use NewZstd.
func Get(id ID) (Codec, error) {
	switch id {
	case None:
		return noneCodec{}, nil
	case Zstd:
		return defaultZstd, nil
	case LZ4:
		return lz4Codec{}, nil
	default:
		return nil, fmt.Errorf("%w: id %d", util.ErrUnknownCompression, uint8(id))
	}
}

// --- None ------------------------------------------------------------------

type noneCodec struct{}

func (noneCodec) ID() ID                     { return None }
func (noneCodec) Compress(src []byte) []byte { return src }
func (noneCodec) Decompress(src []byte, outLen int) ([]byte, error) {
	if len(src) != outLen {
		return nil, fmt.Errorf("%w: none length %d != %d", util.ErrCorrupt, len(src), outLen)
	}
	return src, nil
}

// --- Zstd ------------------------------------------------------------------

type zstdCodec struct {
	enc *zstd.Encoder
}

var defaultZstd = mustZstd(zstd.SpeedDefault)

func mustZstd(level zstd.EncoderLevel) zstdCodec {
	c, err := NewZstd(int(level))
	if err != nil {
		panic("ntcf: zstd encoder init: " + err.Error())
	}
	return c.(zstdCodec)
}

// NewZstd returns a zstd codec at the given klauspost EncoderLevel (1..4 map to
// fastest..best). Callers that pack many files should reuse the returned codec.
func NewZstd(level int) (Codec, error) {
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)),
		zstd.WithEncoderConcurrency(1),
	)
	if err != nil {
		return nil, err
	}
	return zstdCodec{enc: enc}, nil
}

func (zstdCodec) ID() ID { return Zstd }

func (c zstdCodec) Compress(src []byte) []byte {
	return c.enc.EncodeAll(src, make([]byte, 0, len(src)/2+8))
}

func (zstdCodec) Decompress(src []byte, outLen int) ([]byte, error) {
	out, err := zstdDecoder.DecodeAll(src, make([]byte, 0, outLen))
	if err != nil {
		return nil, fmt.Errorf("%w: zstd: %v", util.ErrCorrupt, err)
	}
	if len(out) != outLen {
		return nil, fmt.Errorf("%w: zstd length %d != %d", util.ErrCorrupt, len(out), outLen)
	}
	return out, nil
}

// --- LZ4 -------------------------------------------------------------------
//
// LZ4 uses the block API and is made self-describing with a one-byte header:
// 0 => payload stored raw (incompressible), 1 => payload is an LZ4 block. This
// keeps decoding independent of any writer-side "did it help?" heuristic.

type lz4Codec struct{}

func (lz4Codec) ID() ID { return LZ4 }

func (lz4Codec) Compress(src []byte) []byte {
	bound := lz4.CompressBlockBound(len(src))
	buf := make([]byte, 1+bound)
	var c lz4.Compressor
	n, err := c.CompressBlock(src, buf[1:])
	if err != nil || n == 0 || n >= len(src) {
		out := make([]byte, 1+len(src))
		out[0] = 0
		copy(out[1:], src)
		return out
	}
	buf[0] = 1
	return buf[:1+n]
}

func (lz4Codec) Decompress(src []byte, outLen int) ([]byte, error) {
	if len(src) < 1 {
		if outLen == 0 {
			return []byte{}, nil
		}
		return nil, fmt.Errorf("%w: lz4 empty", util.ErrTruncated)
	}
	flag, payload := src[0], src[1:]
	switch flag {
	case 0:
		if len(payload) != outLen {
			return nil, fmt.Errorf("%w: lz4 raw length %d != %d", util.ErrCorrupt, len(payload), outLen)
		}
		out := make([]byte, outLen)
		copy(out, payload)
		return out, nil
	case 1:
		dst := make([]byte, outLen)
		n, err := lz4.UncompressBlock(payload, dst)
		if err != nil {
			return nil, fmt.Errorf("%w: lz4: %v", util.ErrCorrupt, err)
		}
		if n != outLen {
			return nil, fmt.Errorf("%w: lz4 length %d != %d", util.ErrCorrupt, n, outLen)
		}
		return dst, nil
	default:
		return nil, fmt.Errorf("%w: lz4 flag %d", util.ErrCorrupt, flag)
	}
}
