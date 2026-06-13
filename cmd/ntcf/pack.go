package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ntcf/ntcf/internal/adapter"
	"github.com/ntcf/ntcf/internal/ingest"
	"github.com/ntcf/ntcf/pkg/ntcf"
	"github.com/spf13/cobra"
)

// countingReader tracks how many input bytes were consumed, for ratio reporting.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func newPackCmd() *cobra.Command {
	var (
		source      string
		out         string
		compression string
		zstdLevel   int
		segmentRows int
		inverted    bool
	)
	cmd := &cobra.Command{
		Use:   "pack [input...]",
		Short: "Pack raw telemetry into a .ntcf file",
		Long: "Read telemetry from the given files (or stdin) using the chosen source\n" +
			"adapter and write a compressed, indexed .ntcf file.\n\n" +
			"Sources: " + strings.Join(adapter.Names(), ", "),
		RunE: func(_ *cobra.Command, args []string) error {
			comp, err := parseCompression(compression)
			if err != nil {
				return err
			}
			in, closeIn, err := openInputs(args)
			if err != nil {
				return err
			}
			defer closeIn()
			cr := &countingReader{r: in}

			if out == "" {
				return fmt.Errorf("output file required (-o)")
			}
			f, err := os.Create(out)
			if err != nil {
				return err
			}
			defer f.Close()

			stats, err := ingest.Run(context.Background(), cr, f, ingest.Options{
				Source:        source,
				Compression:   comp,
				ZstdLevel:     zstdLevel,
				SegmentRows:   segmentRows,
				BuildInverted: inverted,
			})
			if err != nil {
				return err
			}
			if err := f.Sync(); err != nil {
				return err
			}
			fi, _ := f.Stat()
			outBytes := fi.Size()
			ratio := 0.0
			if outBytes > 0 {
				ratio = float64(cr.n) / float64(outBytes)
			}
			fmt.Fprintf(os.Stdout,
				"packed %d records (%d skipped) from %s into %s\n  input:  %s\n  output: %s\n  ratio:  %.2fx\n",
				stats.Records, stats.Skipped, humanBytes(cr.n), out,
				humanBytes(cr.n), humanBytes(outBytes), ratio)
			return nil
		},
	}
	cmd.Flags().StringVar(&source, "source", "generic-flow", "telemetry source adapter")
	cmd.Flags().StringVarP(&out, "out", "o", "", "output .ntcf file (required)")
	cmd.Flags().StringVar(&compression, "compression", "zstd", "entropy codec: zstd|lz4|none")
	cmd.Flags().IntVar(&zstdLevel, "zstd-level", 3, "zstd level 1..4 (fastest..best)")
	cmd.Flags().IntVar(&segmentRows, "segment-rows", 65536, "rows per segment")
	cmd.Flags().BoolVar(&inverted, "inverted", false, "also store inverted indexes (larger files, faster point lookups)")
	return cmd
}

func parseCompression(s string) (ntcf.Compression, error) {
	switch strings.ToLower(s) {
	case "none":
		return ntcf.CompressionNone, nil
	case "zstd":
		return ntcf.CompressionZstd, nil
	case "lz4":
		return ntcf.CompressionLZ4, nil
	default:
		return 0, fmt.Errorf("unknown compression %q (want zstd|lz4|none)", s)
	}
}

// openInputs returns a reader over the concatenation of the named files, or
// stdin when no files are given.
func openInputs(args []string) (io.Reader, func(), error) {
	if len(args) == 0 {
		return os.Stdin, func() {}, nil
	}
	var readers []io.Reader
	var files []*os.File
	for _, a := range args {
		f, err := os.Open(a)
		if err != nil {
			for _, of := range files {
				of.Close()
			}
			return nil, nil, err
		}
		files = append(files, f)
		readers = append(readers, f)
		readers = append(readers, strings.NewReader("\n")) // guard against missing trailing newline
	}
	return io.MultiReader(readers...), func() {
		for _, f := range files {
			f.Close()
		}
	}, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
