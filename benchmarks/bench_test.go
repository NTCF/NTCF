// Package benchmarks holds reproducible Go benchmarks for NTCF: pack
// throughput, query latency, and search latency over synthetic telemetry.
//
// Run:  go test ./benchmarks/ -bench=. -benchmem
package benchmarks

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/ntcf/ntcf/internal/adapter"
	"github.com/ntcf/ntcf/internal/datagen"
	"github.com/ntcf/ntcf/pkg/ntcf"
)

const benchRecords = 100000

func genLines(b *testing.B, source string) [][]byte {
	b.Helper()
	var buf bytes.Buffer
	if err := datagen.Generate(source, benchRecords, 1, &buf); err != nil {
		b.Fatal(err)
	}
	var lines [][]byte
	sc := bufio.NewScanner(&buf)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		cp := make([]byte, len(sc.Bytes()))
		copy(cp, sc.Bytes())
		lines = append(lines, cp)
	}
	return lines
}

func pack(b *testing.B, source string, lines [][]byte) []byte {
	b.Helper()
	ad, _ := adapter.Get(source)
	var out bytes.Buffer
	w, err := ntcf.NewWriter(&out, ad.Schema(), ntcf.DefaultWriterOptions())
	if err != nil {
		b.Fatal(err)
	}
	for _, ln := range lines {
		rec, derr := ad.Decode(ln)
		if derr != nil {
			continue
		}
		if err := w.Append(rec); err != nil {
			b.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
	return out.Bytes()
}

func BenchmarkPack(b *testing.B) {
	for _, source := range datagen.Sources {
		b.Run(source, func(b *testing.B) {
			lines := genLines(b, source)
			var rawBytes int64
			for _, ln := range lines {
				rawBytes += int64(len(ln)) + 1
			}
			b.ResetTimer()
			b.SetBytes(rawBytes)
			for i := 0; i < b.N; i++ {
				_ = pack(b, source, lines)
			}
		})
	}
}

func BenchmarkQueryCount(b *testing.B) {
	lines := genLines(b, "honeypot")
	data := pack(b, "honeypot", lines)
	r, err := ntcf.NewReader(data)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Query("SELECT count(*) FROM events WHERE country='CN'"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSearchIP(b *testing.B) {
	lines := genLines(b, "honeypot")
	data := pack(b, "honeypot", lines)
	r, err := ntcf.NewReader(data)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Search("port", "22", 100); err != nil {
			b.Fatal(err)
		}
	}
}
