package main

import (
	"os"

	"github.com/ntcf/ntcf/pkg/ntcf"
	"github.com/spf13/cobra"
)

func newSearchCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "search <field> <value> <file.ntcf>",
		Short: "Find rows by field/value (ip, port, asn, country, or any column)",
		Long: "Search a file for rows matching a field/value, using bloom and zone-map\n" +
			"pruning to skip segments that cannot contain the value.\n\n" +
			"Examples:\n" +
			"  ntcf search ip 203.0.113.5 events.ntcf\n" +
			"  ntcf search asn 15169 events.ntcf\n" +
			"  ntcf search country RU events.ntcf\n" +
			"  ntcf search port 22 events.ntcf",
		Args: cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			field, value, path := args[0], args[1], args[2]
			r, err := ntcf.Open(path)
			if err != nil {
				return err
			}
			defer r.Close()
			res, err := r.Search(field, value, limit)
			if err != nil {
				return err
			}
			printResult(os.Stdout, res)
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum rows to return (0 = engine default)")
	return cmd
}
