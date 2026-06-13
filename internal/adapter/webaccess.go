package adapter

import (
	"strconv"
	"strings"
	"time"

	"github.com/ntcf/ntcf/internal/row"
	"github.com/ntcf/ntcf/internal/schema"
	"github.com/ntcf/ntcf/internal/util"
)

func init() { Register("web-access", func() Adapter { return &webAccess{} }) }

// webAccess decodes Apache/nginx Common and Combined Log Format access lines
// (IIS W3C support is a roadmap item). It demonstrates text-line ingestion and
// dictionary encoding over HTTP methods and status codes alongside
// high-cardinality URL/user-agent columns that fall back to raw+entropy coding.
type webAccess struct{}

func (webAccess) Name() string { return "web-access" }

func (webAccess) Schema() *schema.Schema {
	return &schema.Schema{
		ID:      3,
		Name:    "web-access",
		Version: 1,
		Columns: []schema.Column{
			{Name: "timestamp", Type: schema.TypeTimestamp},
			{Name: "srcip", Type: schema.TypeIP, Indexed: true},
			{Name: "method", Type: schema.TypeEnum, Indexed: true},
			{Name: "path", Type: schema.TypeString, Indexed: true},
			{Name: "status", Type: schema.TypeUint, Indexed: true},
			{Name: "bytes", Type: schema.TypeUint},
			{Name: "referer", Type: schema.TypeString, Nullable: true},
			{Name: "useragent", Type: schema.TypeString, Indexed: true, Nullable: true},
		},
	}
}

const clfTime = "02/Jan/2006:15:04:05 -0700"

func (webAccess) Decode(line []byte) (row.Record, error) {
	s := string(trimSpace(line))
	if s == "" || s[0] == '#' {
		return nil, ErrSkip
	}
	tok := splitCLF(s)
	if len(tok) < 7 {
		return nil, ErrSkip
	}
	host := tok[0]
	tsRaw := tok[3]
	request := tok[4]
	statusRaw := tok[5]
	bytesRaw := tok[6]

	t, err := time.Parse(clfTime, tsRaw)
	if err != nil {
		return nil, ErrSkip
	}

	method, path := "", ""
	if parts := strings.SplitN(request, " ", 3); len(parts) >= 2 {
		method, path = parts[0], parts[1]
	} else {
		return nil, ErrSkip
	}

	ipVal := row.NullVal()
	if b, ok := util.NormalizeIP(host); ok {
		ipVal = row.BytesVal(b)
	}
	status := row.NullVal()
	if n, err := strconv.ParseUint(statusRaw, 10, 64); err == nil {
		status = row.IntVal(n)
	}
	nbytes := row.IntVal(0)
	if bytesRaw != "-" {
		if n, err := strconv.ParseUint(bytesRaw, 10, 64); err == nil {
			nbytes = row.IntVal(n)
		}
	}

	referer := row.NullVal()
	useragent := row.NullVal()
	if len(tok) >= 9 {
		if tok[7] != "" && tok[7] != "-" {
			referer = row.BytesVal([]byte(tok[7]))
		}
		if tok[8] != "" && tok[8] != "-" {
			useragent = row.BytesVal([]byte(tok[8]))
		}
	}

	return row.Record{
		row.IntVal(uint64(t.UnixNano())),
		ipVal,
		row.BytesVal([]byte(method)),
		row.BytesVal([]byte(path)),
		status,
		nbytes,
		referer,
		useragent,
	}, nil
}

// splitCLF tokenises a CLF/Combined line, treating "quoted" and [bracketed]
// spans as single tokens. Surrounding quotes/brackets are stripped from the
// returned tokens.
func splitCLF(s string) []string {
	var tokens []string
	i := 0
	n := len(s)
	for i < n {
		for i < n && s[i] == ' ' {
			i++
		}
		if i >= n {
			break
		}
		var end byte
		switch s[i] {
		case '"':
			end = '"'
		case '[':
			end = ']'
		}
		if end != 0 {
			i++ // skip opening
			start := i
			for i < n && s[i] != end {
				i++
			}
			tokens = append(tokens, s[start:i])
			if i < n {
				i++ // skip closing
			}
		} else {
			start := i
			for i < n && s[i] != ' ' {
				i++
			}
			tokens = append(tokens, s[start:i])
		}
	}
	return tokens
}
