package query

import (
	"github.com/ntcf/ntcf/internal/schema"
	"github.com/ntcf/ntcf/internal/store"
)

// Search compiles a field/value lookup into a predicate and executes it,
// returning matching rows. It generalises across schemas by resolving the
// logical field to the relevant column(s):
//
//	ip      -> every TypeIP column (e.g. srcip OR dstip)
//	port    -> every TypePort column (srcport OR dstport)
//	asn     -> the "asn" column
//	country -> the "country" column
//	<other> -> a column whose name equals the field
//
// This is the engine behind `ntcf search ip|asn|country|port <value>`.
func Search(r *store.Reader, field, value string, limit int) (*Result, error) {
	sch := r.Schema()
	cols := resolveSearchColumns(sch, field)
	if len(cols) == 0 {
		return nil, perr("field %q does not map to any column in schema %q", field, sch.Name)
	}
	var where Expr
	for _, name := range cols {
		cmp := Cmp{Col: name, Op: "=", Vals: []string{value}}
		if where == nil {
			where = cmp
		} else {
			where = Or{L: where, R: cmp}
		}
	}
	st := &Stmt{Star: true, Where: where, Limit: limit}
	return Execute(r, st)
}

func resolveSearchColumns(sch *schema.Schema, field string) []string {
	var out []string
	switch field {
	case "ip":
		for _, c := range sch.Columns {
			if c.Type == schema.TypeIP {
				out = append(out, c.Name)
			}
		}
	case "port":
		for _, c := range sch.Columns {
			if c.Type == schema.TypePort {
				out = append(out, c.Name)
			}
		}
	default:
		if sch.Index(field) >= 0 {
			out = append(out, field)
		}
	}
	return out
}
