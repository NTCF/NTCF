package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"os/exec"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ntcf/ntcf/internal/adapter"
	"github.com/ntcf/ntcf/internal/datagen"
	"github.com/ntcf/ntcf/pkg/ntcf"
	"github.com/pierrec/lz4/v4"
	"github.com/spf13/cobra"
)

func newBenchCmd() *cobra.Command {
	var (
		source string
		count  int
		seed   int64
	)
	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Benchmark NTCF against gzip/zstd/lz4/xz on synthetic telemetry",
		Long: "Generate synthetic telemetry, then compare NTCF's columnar+semantic\n" +
			"compression against generic byte compressors on the same raw input.",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runBench(source, count, seed)
		},
	}
	cmd.Flags().StringVar(&source, "source", "honeypot", "telemetry source")
	cmd.Flags().IntVar(&count, "count", 200000, "number of records")
	cmd.Flags().Int64Var(&seed, "seed", 1, "PRNG seed")
	return cmd
}

func runBench(source string, count int, seed int64) error {
	// 1. Generate raw input.
	var raw bytes.Buffer
	if err := datagen.Generate(source, count, seed, &raw); err != nil {
		return err
	}
	rawBytes := raw.Bytes()
	fmt.Printf("source=%s records=%d raw=%s\n\n", source, count, humanBytes(int64(len(rawBytes))))

	// 2. NTCF pack (semantic columnar + zstd).
	ad, ok := adapter.Get(source)
	if !ok {
		return fmt.Errorf("unknown source %q", source)
	}
	var ntcfBuf bytes.Buffer
	start := time.Now()
	w, err := ntcf.NewWriter(&ntcfBuf, ad.Schema(), ntcf.DefaultWriterOptions())
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(rawBytes))
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		rec, derr := ad.Decode(sc.Bytes())
		if derr != nil {
			continue
		}
		if err := w.Append(rec); err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	ntcfDur := time.Since(start)

	type row struct {
		name string
		size int
		dur  time.Duration
	}
	results := []row{{"ntcf", ntcfBuf.Len(), ntcfDur}}

	// 3. Generic compressors over the same raw bytes.
	add := func(name string, f func() int) {
		n, dur := timeIt(f)
		results = append(results, row{name, n, dur})
	}
	add("gzip-6", func() int { return gzipSize(rawBytes) })
	add("zstd-3", func() int { return zstdSize(rawBytes) })
	add("lz4", func() int { return lz4Size(rawBytes) })
	if n, dur, ok := xzSize(rawBytes); ok {
		results = append(results, row{"xz", n, dur})
	}

	// 4. Print comparison.
	fmt.Printf("%-8s %12s %10s %10s\n", "codec", "size", "ratio", "time")
	fmt.Printf("%-8s %12s %10s %10s\n", "-----", "----", "-----", "----")
	for _, r := range results {
		ratio := float64(len(rawBytes)) / float64(r.size)
		fmt.Printf("%-8s %12s %9.2fx %10s\n", r.name, humanBytes(int64(r.size)), ratio, r.dur.Round(time.Millisecond))
	}

	// 5. Demonstrate fast search on the NTCF file (no full decompression).
	r, err := ntcf.NewReader(ntcfBuf.Bytes())
	if err != nil {
		return err
	}
	qStart := time.Now()
	res, err := r.Query("SELECT count(*) FROM events")
	if err != nil {
		return err
	}
	fmt.Printf("\nntcf query count(*)=%d in %s\n", res.Count, time.Since(qStart).Round(time.Microsecond))
	return nil
}

func timeIt(f func() int) (int, time.Duration) {
	start := time.Now()
	n := f()
	return n, time.Since(start)
}

func gzipSize(b []byte) int {
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Len()
}

func zstdSize(b []byte) int {
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	defer enc.Close()
	return len(enc.EncodeAll(b, nil))
}

func lz4Size(b []byte) int {
	var buf bytes.Buffer
	w := lz4.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Len()
}

// xzSize shells out to the xz binary if present; returns ok=false otherwise.
func xzSize(b []byte) (int, time.Duration, bool) {
	path, err := exec.LookPath("xz")
	if err != nil {
		return 0, 0, false
	}
	start := time.Now()
	cmd := exec.Command(path, "-6", "-c")
	cmd.Stdin = bytes.NewReader(b)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return 0, 0, false
	}
	return out.Len(), time.Since(start), true
}
