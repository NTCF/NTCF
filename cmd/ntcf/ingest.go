package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ntcf/ntcf/internal/ingest"
	"github.com/spf13/cobra"
)

func newIngestCmd() *cobra.Command {
	var (
		source      string
		out         string
		compression string
		follow      bool
		fromStart   bool
		checkpoint  time.Duration
		segmentRows int
	)
	cmd := &cobra.Command{
		Use:   "ingest [input]",
		Short: "Continuously ingest streaming telemetry into a .ntcf file",
		Long: "Stream telemetry from stdin or a followed file into a .ntcf file,\n" +
			"checkpointing periodically so the output stays crash-recoverable.\n\n" +
			"Examples:\n" +
			"  tail -F /var/log/suricata/eve.json | ntcf ingest --source generic-flow -o live.ntcf\n" +
			"  ntcf ingest --source honeypot --follow -o live.ntcf /var/log/honeypot.json",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			comp, err := parseCompression(compression)
			if err != nil {
				return err
			}
			if out == "" {
				return fmt.Errorf("output file required (-o)")
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			var in io.Reader = os.Stdin
			if len(args) == 1 && args[0] != "-" {
				if follow {
					t, err := ingest.NewTailer(ctx, args[0], !fromStart, 200*time.Millisecond)
					if err != nil {
						return err
					}
					defer t.Close()
					in = t
				} else {
					f, err := os.Open(args[0])
					if err != nil {
						return err
					}
					defer f.Close()
					in = f
				}
			}

			f, err := os.Create(out)
			if err != nil {
				return err
			}
			defer f.Close()

			stats, err := ingest.Run(ctx, in, f, ingest.Options{
				Source:      source,
				Compression: comp,
				SegmentRows: segmentRows,
				Checkpoint:  checkpoint,
			})
			fmt.Fprintf(os.Stderr, "ingested %d records (%d lines, %d skipped) -> %s\n",
				stats.Records, stats.Lines, stats.Skipped, out)
			return err
		},
	}
	cmd.Flags().StringVar(&source, "source", "generic-flow", "telemetry source adapter")
	cmd.Flags().StringVarP(&out, "out", "o", "", "output .ntcf file (required)")
	cmd.Flags().StringVar(&compression, "compression", "zstd", "entropy codec: zstd|lz4|none")
	cmd.Flags().BoolVar(&follow, "follow", false, "follow a growing file (like tail -f)")
	cmd.Flags().BoolVar(&fromStart, "from-start", false, "with --follow, read existing content first")
	cmd.Flags().DurationVar(&checkpoint, "checkpoint", 5*time.Second, "interval between recovery footers")
	cmd.Flags().IntVar(&segmentRows, "segment-rows", 65536, "rows per segment")
	return cmd
}
