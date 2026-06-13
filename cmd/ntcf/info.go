package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ntcf/ntcf/pkg/ntcf"
	"github.com/spf13/cobra"
)

func newInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info <file.ntcf>",
		Short: "Show metadata: schema, row count, time range, segments",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := ntcf.Open(args[0])
			if err != nil {
				return err
			}
			defer r.Close()
			info := r.Info()

			fmt.Printf("File:        %s\n", args[0])
			fmt.Printf("Format:      v%d\n", info.FormatVersion)
			fmt.Printf("Source:      %s\n", orDash(info.SourceType))
			fmt.Printf("Schema:      %s (id %d)\n", info.SchemaName, info.SchemaID)
			fmt.Printf("Rows:        %d\n", info.TotalRows)
			fmt.Printf("Size:        %s\n", humanBytes(info.FileSize))
			fmt.Printf("Segments:    %d\n", len(info.Segments))
			if info.MinTS != 0 || info.MaxTS != 0 {
				fmt.Printf("Time range:  %s .. %s\n",
					time.Unix(0, info.MinTS).UTC().Format(time.RFC3339),
					time.Unix(0, info.MaxTS).UTC().Format(time.RFC3339))
			}
			fmt.Println("\nColumns:")
			printTable(os.Stdout, []string{"name", "type", "indexed"}, columnRows(info))
			return nil
		},
	}
	return cmd
}

func columnRows(info ntcf.Info) [][]string {
	rows := make([][]string, 0, len(info.Columns))
	for _, c := range info.Columns {
		idx := "no"
		if c.Indexed {
			idx = "yes"
		}
		rows = append(rows, []string{c.Name, c.Type, idx})
	}
	return rows
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
