// Package version exposes build and format version metadata for NTCF.
//
// The format version is distinct from the software version: the format
// version gates on-disk compatibility and changes only when the binary
// layout of an .ntcf file changes in a breaking way, whereas the software
// version tracks releases of this module.
package version

import "fmt"

const (
	// Software is the semantic version of the ntcf module/binary. It is
	// overridden at build time via -ldflags "-X .../version.Software=vX.Y.Z".
	Software = "0.1.0-dev"

	// Format is the on-disk NTCF container format version written into every
	// file header. Readers refuse files whose Format major exceeds FormatMax.
	Format uint16 = 1

	// FormatMax is the highest on-disk format version this build can read.
	FormatMax uint16 = 1

	// FormatMin is the lowest on-disk format version this build can read.
	FormatMin uint16 = 1
)

// Commit and BuildDate are injected at build time via -ldflags.
var (
	Commit    = "unknown"
	BuildDate = "unknown"
)

// String returns a human-readable one-line version banner.
func String() string {
	return fmt.Sprintf("ntcf %s (format v%d, commit %s, built %s)",
		Software, Format, Commit, BuildDate)
}

// SupportsFormat reports whether this build can read the given on-disk
// format version.
func SupportsFormat(v uint16) bool {
	return v >= FormatMin && v <= FormatMax
}
