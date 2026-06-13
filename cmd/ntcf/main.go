// Command ntcf is the reference CLI for the Network & Telemetry Compression
// Format: it packs raw telemetry into .ntcf files, inspects them, and runs
// searches and SQL-subset analytics directly against the compressed columns.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"text/tabwriter"

	"github.com/ntcf/ntcf/internal/query"
	"github.com/ntcf/ntcf/pkg/ntcf"
	"github.com/spf13/cobra"
)

var logger *slog.Logger

func main() {
	root := &cobra.Command{
		Use:           "ntcf",
		Short:         "Network & Telemetry Compression Format — pack, search, and query telemetry",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	var verbose bool
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")
	root.PersistentPreRun = func(_ *cobra.Command, _ []string) {
		level := slog.LevelInfo
		if verbose {
			level = slog.LevelDebug
		}
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	}

	root.AddCommand(
		newPackCmd(),
		newInfoCmd(),
		newSearchCmd(),
		newQueryCmd(),
		newIngestCmd(),
		newGenCmd(),
		newBenchCmd(),
		newVersionCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// printResult renders a query/search result to w.
func printResult(w io.Writer, res *ntcf.QueryResult) {
	switch res.Kind {
	case query.KindCount:
		fmt.Fprintf(w, "count: %d\n", res.Count)
	case query.KindTop, query.KindRows:
		printTable(w, res.Columns, res.Rows)
	}
	if res.Pruned > 0 || res.Scanned > 0 {
		fmt.Fprintf(w, "\n(%d segment(s) scanned, %d pruned by index)\n", res.Scanned, res.Pruned)
	}
}

// printTable renders a header and rows using elastic tabstops.
func printTable(w io.Writer, header []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	defer tw.Flush()
	for i, h := range header {
		if i > 0 {
			fmt.Fprint(tw, "\t")
		}
		fmt.Fprint(tw, h)
	}
	fmt.Fprintln(tw)
	for _, row := range rows {
		for i, c := range row {
			if i > 0 {
				fmt.Fprint(tw, "\t")
			}
			fmt.Fprint(tw, c)
		}
		fmt.Fprintln(tw)
	}
}
