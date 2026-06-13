// Package datagen produces deterministic, realistic synthetic telemetry for
// the three reference sources. It backs `ntcf gen` and the benchmark harness,
// so compression and query numbers are reproducible without shipping large
// real-world corpora (which also carry privacy concerns).
//
// Distributions are intentionally skewed the way real telemetry is — a small
// set of noisy source IPs and ASNs dominate, ports cluster on a handful of
// services, most honeypot events are failed logins — because that skew is
// exactly what NTCF's dictionary/RLE/bitpack encodings exploit. Generating
// uniform-random data would understate real-world ratios.
package datagen

import (
	"bufio"
	"fmt"
	"io"
	"math/rand"
	"time"
)

// Sources lists the generatable source names.
var Sources = []string{"generic-flow", "honeypot", "web-access"}

// Generate writes count synthetic records for source to w, seeded for
// reproducibility. The output format matches what the corresponding adapter
// parses (JSON lines for flow/honeypot, Combined Log Format for web-access).
func Generate(source string, count int, seed int64, w io.Writer) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush()
	r := rand.New(rand.NewSource(seed))
	g := newGen(r)
	switch source {
	case "generic-flow":
		return g.flow(bw, count)
	case "honeypot":
		return g.honeypot(bw, count)
	case "web-access":
		return g.web(bw, count)
	default:
		return fmt.Errorf("datagen: unknown source %q", source)
	}
}

type gen struct {
	r      *rand.Rand
	srcIPs []string
	asns   []uint32
	asnCC  []string // country aligned with asns
	ts     time.Time
}

func newGen(r *rand.Rand) *gen {
	g := &gen{r: r, ts: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)}
	// A skewed pool of noisy source IPs (scanners/attackers reused heavily).
	for i := 0; i < 400; i++ {
		g.srcIPs = append(g.srcIPs, fmt.Sprintf("%d.%d.%d.%d",
			45+r.Intn(180), r.Intn(256), r.Intn(256), 1+r.Intn(254)))
	}
	// ASN -> country pairs drawn from real large networks.
	pairs := []struct {
		asn uint32
		cc  string
	}{
		{4134, "CN"}, {4837, "CN"}, {14061, "US"}, {16509, "US"}, {15169, "US"},
		{13335, "US"}, {8075, "US"}, {24940, "DE"}, {16276, "FR"}, {12389, "RU"},
		{8359, "RU"}, {9009, "GB"}, {45102, "CN"}, {37963, "CN"}, {3462, "TW"},
	}
	for _, p := range pairs {
		g.asns = append(g.asns, p.asn)
		g.asnCC = append(g.asnCC, p.cc)
	}
	return g
}

// nextTS advances the clock by a small jittered interval (near-monotonic, the
// pattern delta-of-delta timestamp coding is built for).
func (g *gen) nextTS() time.Time {
	g.ts = g.ts.Add(time.Duration(g.r.Intn(2_000_000)+100_000) * time.Nanosecond)
	return g.ts
}

// zipfIdx returns a skewed index into [0,n): low indices much more frequent.
func (g *gen) zipfIdx(n int) int {
	// Square of a uniform biases toward 0 cheaply and deterministically.
	x := g.r.Float64()
	return int(x * x * float64(n))
}

func (g *gen) srcIP() string { return g.srcIPs[g.zipfIdx(len(g.srcIPs))] }

func (g *gen) asn() (uint32, string) {
	i := g.zipfIdx(len(g.asns))
	return g.asns[i], g.asnCC[i]
}

func (g *gen) flow(w io.Writer, count int) error {
	dports := []int{443, 80, 53, 22, 3389, 8080, 25, 123}
	protos := []string{"tcp", "tcp", "tcp", "udp"}
	events := []string{"flow", "flow", "flow", "scan", "rejected"}
	for i := 0; i < count; i++ {
		asn, cc := g.asn()
		_, err := fmt.Fprintf(w,
			`{"timestamp":"%s","srcip":"%s","dstip":"10.%d.%d.%d","srcport":%d,"dstport":%d,"protocol":"%s","asn":%d,"country":"%s","eventtype":"%s","bytes":%d,"packets":%d}`+"\n",
			g.nextTS().Format(time.RFC3339Nano), g.srcIP(),
			g.r.Intn(256), g.r.Intn(256), 1+g.r.Intn(254),
			1024+g.r.Intn(64000), dports[g.zipfIdx(len(dports))],
			protos[g.r.Intn(len(protos))], asn, cc,
			events[g.zipfIdx(len(events))], 40+g.r.Intn(60000), 1+g.r.Intn(40))
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *gen) honeypot(w io.Writer, count int) error {
	services := []struct {
		proto string
		port  int
	}{{"ssh", 22}, {"rdp", 3389}, {"telnet", 23}, {"smtp", 25}, {"smb", 445}, {"mssql", 1433}}
	events := []string{"login.failed", "login.failed", "login.failed", "login.failed", "scan", "login.success"}
	users := []string{"root", "admin", "user", "test", "oracle", "ubuntu", "guest", "postgres", "git", "administrator"}
	passes := []string{"123456", "password", "admin", "root", "12345678", "qwerty", "1qaz2wsx", "letmein", "P@ssw0rd"}
	for i := 0; i < count; i++ {
		svc := services[g.zipfIdx(len(services))]
		asn, cc := g.asn()
		ev := events[g.zipfIdx(len(events))]
		line := fmt.Sprintf(
			`{"timestamp":"%s","srcip":"%s","srcport":%d,"dstport":%d,"protocol":"%s","eventtype":"%s","asn":%d,"country":"%s"`,
			g.nextTS().Format(time.RFC3339Nano), g.srcIP(), 1024+g.r.Intn(64000),
			svc.port, svc.proto, ev, asn, cc)
		if ev != "scan" {
			line += fmt.Sprintf(`,"username":"%s","password":"%s"`, users[g.zipfIdx(len(users))], passes[g.zipfIdx(len(passes))])
		}
		line += "}"
		if _, err := io.WriteString(w, line+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func (g *gen) web(w io.Writer, count int) error {
	methods := []string{"GET", "GET", "GET", "GET", "POST", "HEAD"}
	paths := []string{"/", "/index.html", "/login", "/wp-login.php", "/admin", "/api/v1/users", "/favicon.ico", "/static/app.js", "/.env", "/phpmyadmin"}
	statuses := []int{200, 200, 200, 304, 404, 403, 301, 500}
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
		"curl/7.88.1", "python-requests/2.31.0", "Googlebot/2.1",
	}
	for i := 0; i < count; i++ {
		_, err := fmt.Fprintf(w,
			`%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"`+"\n",
			g.srcIP(), g.nextTS().Format("02/Jan/2006:15:04:05 -0700"),
			methods[g.r.Intn(len(methods))], paths[g.zipfIdx(len(paths))],
			statuses[g.zipfIdx(len(statuses))], g.r.Intn(50000), uas[g.zipfIdx(len(uas))])
		if err != nil {
			return err
		}
	}
	return nil
}
