// Package ingest is the streaming ingestion pipeline: it reads telemetry line
// by line from a reader (a file, stdin, or a `tail -f`/`journalctl -f` pipe),
// decodes each line through an adapter, and appends the records to an NTCF
// writer, periodically checkpointing so the output is crash-recoverable.
//
// The pipeline is context-cancellable and applies natural backpressure: it
// reads and encodes synchronously, so a slow disk slows reading rather than
// growing an unbounded queue. A single goroutine owns the writer, keeping the
// hot path race-free.
package ingest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ntcf/ntcf/internal/adapter"
	"github.com/ntcf/ntcf/pkg/ntcf"
)

// Stats summarises an ingestion run.
type Stats struct {
	Lines   int64
	Records int64
	Skipped int64
}

// Options configures an ingestion run.
type Options struct {
	Source        string
	Compression   ntcf.Compression
	ZstdLevel     int
	SegmentRows   int
	BuildInverted bool          // store Roaring inverted indexes (larger, faster point lookups)
	Checkpoint    time.Duration // how often to append a recovery footer (0 = none)
	MaxLineBytes  int           // scanner buffer cap (default 4 MiB)
}

// DefaultMaxLineBytes bounds a single input line so a hostile or runaway source
// cannot exhaust memory.
const DefaultMaxLineBytes = 4 << 20

// Run consumes lines from in, decodes them with the configured adapter, and
// writes NTCF records to out until in is exhausted or ctx is cancelled. It
// returns ingestion statistics. The writer is always closed (final footer
// written) before returning, even on cancellation, so the output is valid.
func Run(ctx context.Context, in io.Reader, out io.Writer, opts Options) (Stats, error) {
	var stats Stats
	ad, ok := adapter.Get(opts.Source)
	if !ok {
		return stats, fmt.Errorf("ntcf: unknown source %q", opts.Source)
	}
	wopts := ntcf.DefaultWriterOptions()
	wopts.Compression = opts.Compression
	if opts.ZstdLevel > 0 {
		wopts.ZstdLevel = opts.ZstdLevel
	}
	if opts.SegmentRows > 0 {
		wopts.SegmentRows = opts.SegmentRows
	}
	wopts.BuildInverted = opts.BuildInverted
	wopts.SourceType = opts.Source

	w, err := ntcf.NewWriter(out, ad.Schema(), wopts)
	if err != nil {
		return stats, err
	}

	maxLine := opts.MaxLineBytes
	if maxLine <= 0 {
		maxLine = DefaultMaxLineBytes
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)

	var nextCheckpoint time.Time
	if opts.Checkpoint > 0 {
		nextCheckpoint = time.Now().Add(opts.Checkpoint)
	}

	runErr := func() error {
		for sc.Scan() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			stats.Lines++
			rec, derr := ad.Decode(sc.Bytes())
			if derr != nil {
				if errors.Is(derr, adapter.ErrSkip) {
					stats.Skipped++
					continue
				}
				return derr
			}
			if err := w.Append(rec); err != nil {
				return err
			}
			stats.Records++
			if opts.Checkpoint > 0 && time.Now().After(nextCheckpoint) {
				if err := w.Checkpoint(); err != nil {
					return err
				}
				nextCheckpoint = time.Now().Add(opts.Checkpoint)
			}
		}
		return sc.Err()
	}()

	// Always finalise the file, preserving the primary error if any.
	closeErr := w.Close()
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return stats, runErr
	}
	return stats, closeErr
}
