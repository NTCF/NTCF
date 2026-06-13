package util

import "net/netip"

// NormalizeIP parses a textual IPv4 or IPv6 address and returns its canonical
// 16-byte form (IPv4 is stored as a v4-in-v6 mapped address). The fixed 16-byte
// representation lets a single column hold both families, gives correct
// lexicographic ordering for zone-map pruning (all v4 share the ::ffff: prefix
// and order correctly among themselves), and lets dictionary encoding collapse
// the heavy IP repetition typical of honeypot and web telemetry.
//
// Both the ingestion adapters and the query/search engine call this, so a
// stored address and a search term normalise identically.
func NormalizeIP(s string) ([]byte, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil, false
	}
	b := addr.As16()
	out := make([]byte, 16)
	copy(out, b[:])
	return out, true
}

// IPString renders a 16-byte normalized address back to text, unmapping
// v4-in-v6 addresses to dotted-quad form. Invalid lengths render as "?".
func IPString(b []byte) string {
	if len(b) != 16 {
		return "?"
	}
	var a [16]byte
	copy(a[:], b)
	addr := netip.AddrFrom16(a).Unmap()
	return addr.String()
}
