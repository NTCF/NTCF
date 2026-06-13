// Command writeread is a minimal, runnable example of the NTCF public API: it
// defines a schema, writes a few records to a .ntcf file, then reopens it and
// runs a search and an aggregate query.
//
//	go run ./examples/writeread
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ntcf/ntcf/pkg/ntcf"
)

func main() {
	sch := &ntcf.Schema{
		ID:      100,
		Name:    "demo-events",
		Version: 1,
		Columns: []ntcf.Column{
			{Name: "timestamp", Type: ntcf.TypeTimestamp},
			{Name: "srcip", Type: ntcf.TypeIP, Indexed: true},
			{Name: "dstport", Type: ntcf.TypePort, Indexed: true},
			{Name: "country", Type: ntcf.TypeEnum, Indexed: true, Nullable: true},
			{Name: "eventtype", Type: ntcf.TypeEnum, Indexed: true},
		},
	}

	path := "demo.ntcf"
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}

	w, err := ntcf.NewWriter(f, sch, ntcf.DefaultWriterOptions())
	if err != nil {
		log.Fatal(err)
	}

	base := time.Now().UnixNano()
	samples := []struct {
		ip      string
		port    uint64
		country string
		event   string
	}{
		{"203.0.113.5", 22, "RU", "ssh.bruteforce"},
		{"203.0.113.5", 22, "RU", "ssh.bruteforce"},
		{"198.51.100.9", 3389, "CN", "rdp.scan"},
		{"192.0.2.1", 22, "", "ssh.login.success"}, // unknown country -> null
	}
	for i, s := range samples {
		ip16, ok := ntcf.NormalizeIP(s.ip)
		if !ok {
			log.Fatalf("bad ip %q", s.ip)
		}
		country := ntcf.BytesVal([]byte(s.country))
		if s.country == "" {
			country = ntcf.NullVal()
		}
		rec := ntcf.Record{
			ntcf.IntVal(uint64(base) + uint64(i)*1_000_000),
			ntcf.BytesVal(ip16),
			ntcf.IntVal(s.port),
			country,
			ntcf.BytesVal([]byte(s.event)),
		}
		if err := w.Append(rec); err != nil {
			log.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}
	_ = f.Close()

	r, err := ntcf.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	info := r.Info()
	fmt.Printf("file %s: %d rows, %d column(s)\n", path, info.TotalRows, len(info.Columns))

	res, _ := r.Query("SELECT count(*) FROM events WHERE country='RU'")
	fmt.Printf("RU events: %d\n", res.Count)

	top, _ := r.Query("SELECT top(eventtype) FROM events")
	fmt.Printf("top event: %s (%s)\n", top.Rows[0][0], top.Rows[0][1])

	hits, _ := r.Search("ip", "203.0.113.5", 10)
	fmt.Printf("rows for 203.0.113.5: %d\n", len(hits.Rows))
}
