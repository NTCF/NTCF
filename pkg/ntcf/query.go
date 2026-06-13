package ntcf

import "github.com/ntcf/ntcf/internal/query"

// QueryResultKind discriminates the shape of a QueryResult.
type QueryResultKind = query.ResultKind

// Query result kinds.
const (
	ResultCount = query.KindCount
	ResultTop   = query.KindTop
	ResultRows  = query.KindRows
)

// QueryResult is the outcome of Query or Search.
type QueryResult = query.Result

// Query parses and executes a SQL-subset statement against the file. See the
// query package documentation for the supported grammar.
func (r *Reader) Query(q string) (*QueryResult, error) {
	st, err := query.Parse(q)
	if err != nil {
		return nil, err
	}
	return query.Execute(r.store(), st)
}

// Search runs a field/value lookup (ip, port, asn, country, or any column name)
// returning matching rows up to limit (0 = default cap).
func (r *Reader) Search(field, value string, limit int) (*QueryResult, error) {
	return query.Search(r.store(), field, value, limit)
}
