package ingest

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ntcf/ntcf/internal/datagen"
	"github.com/ntcf/ntcf/internal/store"
	"github.com/ntcf/ntcf/pkg/ntcf"
)

func TestIngestRoundTrip(t *testing.T) {
	var in bytes.Buffer
	if err := datagen.Generate("honeypot", 5000, 1, &in); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	stats, err := Run(context.Background(), &in, &out, Options{
		Source:      "honeypot",
		Compression: ntcf.CompressionZstd,
		SegmentRows: 500,
		Checkpoint:  time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records == 0 {
		t.Fatal("no records ingested")
	}
	r, err := ntcf.NewReader(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Info().TotalRows; int64(got) != stats.Records {
		t.Fatalf("file rows=%d != ingested %d", got, stats.Records)
	}
}

// TestCrashRecovery simulates a writer crash by truncating the file before its
// final footer, then verifies the last checkpoint footer is recoverable.
func TestCrashRecovery(t *testing.T) {
	var in bytes.Buffer
	if err := datagen.Generate("honeypot", 6000, 2, &in); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Run(context.Background(), &in, &out, Options{
		Source:      "honeypot",
		Compression: ntcf.CompressionZstd,
		SegmentRows: 400,
		Checkpoint:  time.Nanosecond, // checkpoint aggressively to embed many footers
	}); err != nil {
		t.Fatal(err)
	}
	full := out.Bytes()

	// Lop off the trailing 20% — as if the process died mid-write. The final
	// footer is gone, but earlier checkpoint footers remain intact.
	truncated := make([]byte, len(full)*80/100)
	copy(truncated, full)

	if _, err := store.New(truncated); err == nil {
		t.Fatal("expected normal open to fail on truncated file")
	}
	r, recovered, err := store.Recover(truncated)
	if err != nil {
		t.Fatalf("recover failed: %v", err)
	}
	if !recovered {
		t.Fatal("expected recovery path to be used")
	}
	rows := r.Footer().TotalRows
	if rows == 0 || rows > 6000 {
		t.Fatalf("recovered rows=%d, want 0<rows<=6000", rows)
	}
	// The recovered file must be fully readable: decode every segment's first column.
	for segIdx := range r.Footer().Segments {
		if _, err := r.Column(segIdx, 0); err != nil {
			t.Fatalf("recovered segment %d unreadable: %v", segIdx, err)
		}
	}
	t.Logf("recovered %d of 6000 rows after truncation", rows)
}
