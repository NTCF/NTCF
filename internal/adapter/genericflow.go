package adapter

import (
	"encoding/json"

	"github.com/ntcf/ntcf/internal/row"
	"github.com/ntcf/ntcf/internal/schema"
)

func init() { Register("generic-flow", func() Adapter { return &genericFlow{} }) }

// genericFlow decodes JSON-lines flow/event records into the backbone schema
// that most telemetry maps onto. Unknown/missing fields become nulls.
type genericFlow struct{}

func (genericFlow) Name() string { return "generic-flow" }

func (genericFlow) Schema() *schema.Schema {
	return &schema.Schema{
		ID:      1,
		Name:    "generic-flow",
		Version: 1,
		Columns: []schema.Column{
			{Name: "timestamp", Type: schema.TypeTimestamp},
			{Name: "srcip", Type: schema.TypeIP, Indexed: true},
			{Name: "dstip", Type: schema.TypeIP, Indexed: true},
			{Name: "srcport", Type: schema.TypePort},
			{Name: "dstport", Type: schema.TypePort, Indexed: true},
			{Name: "protocol", Type: schema.TypeEnum, Indexed: true},
			{Name: "asn", Type: schema.TypeUint, Indexed: true},
			{Name: "country", Type: schema.TypeEnum, Indexed: true, Nullable: true},
			{Name: "eventtype", Type: schema.TypeEnum, Indexed: true},
			{Name: "bytes", Type: schema.TypeUint},
			{Name: "packets", Type: schema.TypeUint},
		},
	}
}

func (genericFlow) Decode(line []byte) (row.Record, error) {
	if len(trimSpace(line)) == 0 {
		return nil, ErrSkip
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, ErrSkip
	}
	tsStr, ok := asString(m, "timestamp", "ts", "@timestamp")
	if !ok {
		return nil, ErrSkip
	}
	tsNanos, ok := parseTimeNanos(tsStr)
	if !ok {
		return nil, ErrSkip
	}
	country, hasCountry := asString(m, "country", "geoip_country", "src_country")
	proto, hasProto := asString(m, "protocol", "proto")
	ev, hasEv := asString(m, "eventtype", "event_type", "event")

	return row.Record{
		row.IntVal(uint64(tsNanos)),
		ipValue(m, "srcip", "src_ip", "saddr"),
		ipValue(m, "dstip", "dst_ip", "daddr"),
		uintValue(m, "srcport", "src_port", "sport"),
		uintValue(m, "dstport", "dst_port", "dport"),
		enumValue(proto, hasProto),
		uintValue(m, "asn", "src_asn"),
		enumValue(upperCountry(country), hasCountry),
		enumValue(ev, hasEv),
		uintValue(m, "bytes", "in_bytes", "orig_bytes"),
		uintValue(m, "packets", "in_pkts"),
	}, nil
}

func trimSpace(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	j := len(b)
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\r' || b[j-1] == '\n') {
		j--
	}
	return b[i:j]
}
