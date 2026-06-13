package adapter

import (
	"encoding/json"

	"github.com/ntcf/ntcf/internal/row"
	"github.com/ntcf/ntcf/internal/schema"
)

func init() { Register("honeypot", func() Adapter { return &honeypot{} }) }

// honeypot decodes JSON-lines honeypot attack events (SSH/RDP/Telnet/SMTP/HTTP
// brute-force and scan activity). It showcases dictionary encoding over event
// types, protocols, usernames and country codes, plus heavy IP/ASN repetition.
type honeypot struct{}

func (honeypot) Name() string { return "honeypot" }

func (honeypot) Schema() *schema.Schema {
	return &schema.Schema{
		ID:      2,
		Name:    "honeypot",
		Version: 1,
		Columns: []schema.Column{
			{Name: "timestamp", Type: schema.TypeTimestamp},
			{Name: "srcip", Type: schema.TypeIP, Indexed: true},
			{Name: "srcport", Type: schema.TypePort},
			{Name: "dstport", Type: schema.TypePort, Indexed: true},
			{Name: "protocol", Type: schema.TypeEnum, Indexed: true},
			{Name: "eventtype", Type: schema.TypeEnum, Indexed: true},
			{Name: "username", Type: schema.TypeString, Indexed: true, Nullable: true},
			{Name: "password", Type: schema.TypeString, Nullable: true},
			{Name: "country", Type: schema.TypeEnum, Indexed: true, Nullable: true},
			{Name: "asn", Type: schema.TypeUint, Indexed: true},
		},
	}
}

func (honeypot) Decode(line []byte) (row.Record, error) {
	if len(trimSpace(line)) == 0 {
		return nil, ErrSkip
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, ErrSkip
	}
	tsStr, ok := asString(m, "timestamp", "ts", "@timestamp", "eventtime")
	if !ok {
		return nil, ErrSkip
	}
	tsNanos, ok := parseTimeNanos(tsStr)
	if !ok {
		return nil, ErrSkip
	}
	proto, hasProto := asString(m, "protocol", "proto", "service")
	ev, hasEv := asString(m, "eventtype", "event_type", "event")
	country, hasCountry := asString(m, "country", "geoip_country")

	return row.Record{
		row.IntVal(uint64(tsNanos)),
		ipValue(m, "srcip", "src_ip", "peerIP", "src_host"),
		uintValue(m, "srcport", "src_port", "peerPort"),
		uintValue(m, "dstport", "dst_port", "hostPort"),
		enumValue(proto, hasProto),
		enumValue(ev, hasEv),
		strValue(m, "username", "user"),
		strValue(m, "password", "pass"),
		enumValue(upperCountry(country), hasCountry),
		uintValue(m, "asn", "src_asn"),
	}, nil
}
