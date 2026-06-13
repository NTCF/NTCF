package main

import (
	"os"
	"strings"

	"github.com/ntcf/ntcf/internal/datagen"
	"github.com/spf13/cobra"
)

func newGenCmd() *cobra.Command {
	var (
		source string
		count  int
		seed   int64
		out    string
	)
	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate deterministic synthetic telemetry for demos and benchmarks",
		Long: "Generate realistic, reproducible synthetic telemetry in the input format\n" +
			"of the chosen source. Sources: " + strings.Join(datagen.Sources, ", ") + ".",
		RunE: func(_ *cobra.Command, _ []string) error {
			w := os.Stdout
			if out != "" && out != "-" {
				f, err := os.Create(out)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			return datagen.Generate(source, count, seed, w)
		},
	}
	cmd.Flags().StringVar(&source, "source", "honeypot", "telemetry source to generate")
	cmd.Flags().IntVar(&count, "count", 10000, "number of records to generate")
	cmd.Flags().Int64Var(&seed, "seed", 1, "PRNG seed for reproducibility")
	cmd.Flags().StringVarP(&out, "out", "o", "-", "output file (default stdout)")
	return cmd
}
