package ingest

import (
	"context"
	"io"
	"os"
	"time"
)

// Tailer is an io.Reader that follows a growing file (like `tail -f`): on
// reaching EOF it polls for new data until the context is cancelled, at which
// point Read returns io.EOF so the ingestion loop terminates cleanly.
//
// It is intended for cases where piping `tail -f`/`journalctl -f` into stdin is
// not convenient. For pipes/stdin, no Tailer is needed — a normal blocking read
// already follows the stream.
type Tailer struct {
	ctx      context.Context
	f        *os.File
	interval time.Duration
}

// NewTailer opens path for following from the given start position. Pass
// io.SeekEnd-relative behaviour by setting fromEnd to skip existing content.
func NewTailer(ctx context.Context, path string, fromEnd bool, interval time.Duration) (*Tailer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if fromEnd {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			f.Close()
			return nil, err
		}
	}
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}
	return &Tailer{ctx: ctx, f: f, interval: interval}, nil
}

// Read implements io.Reader, blocking (with polling) at EOF until new data
// arrives or the context is cancelled.
func (t *Tailer) Read(p []byte) (int, error) {
	for {
		n, err := t.f.Read(p)
		if n > 0 {
			return n, nil
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
		select {
		case <-t.ctx.Done():
			return 0, io.EOF
		case <-time.After(t.interval):
		}
	}
}

// Close closes the underlying file.
func (t *Tailer) Close() error { return t.f.Close() }
