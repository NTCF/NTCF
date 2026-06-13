package main

import (
	"os"

	"github.com/ntcf/ntcf/pkg/ntcf"
	"github.com/spf13/cobra"
)

func newQueryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query <sql> <file.ntcf>",
		Short: "Run a SQL-subset query against a file",
		Long: "Execute a SQL-subset query. Supported:\n" +
			"  SELECT count(*) | top(col [, N]) | * | col [, col...] FROM events\n" +
			"  [WHERE pred [AND|OR pred ...]] [LIMIT n]\n" +
			"  pred: col = value | col != value | col < value | col > value | col IN (...)\n\n" +
			"Examples:\n" +
			"  ntcf query \"SELECT count(*) FROM events WHERE country='RU'\" events.ntcf\n" +
			"  ntcf query \"SELECT top(asn) FROM events WHERE dstport=22\" events.ntcf",
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			sql, path := args[0], args[1]
			r, err := ntcf.Open(path)
			if err != nil {
				return err
			}
			defer r.Close()
			res, err := r.Query(sql)
			if err != nil {
				return err
			}
			printResult(os.Stdout, res)
			return nil
		},
	}
	return cmd
}
