package query

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ntcf/ntcf/internal/util"
)

// Expr is a boolean predicate node.
type Expr interface{ isExpr() }

// And is a logical conjunction.
type And struct{ L, R Expr }

// Or is a logical disjunction.
type Or struct{ L, R Expr }

// Cmp is a leaf comparison: Col Op Value(s). Op is one of "=", "!=", "<", ">",
// "in". For "in", Vals holds the set; otherwise Vals has exactly one element.
type Cmp struct {
	Col  string
	Op   string
	Vals []string
}

func (And) isExpr() {}
func (Or) isExpr()  {}
func (Cmp) isExpr() {}

// Agg is an aggregate in the select list: count(*) or top(col, N).
type Agg struct {
	Func string // "count" | "top"
	Col  string // "*" for count
	N    int    // top-N count
}

// Stmt is a parsed query. Exactly one of Aggregate, Star, or Projection is set.
type Stmt struct {
	Aggregate  *Agg
	Star       bool
	Projection []string
	Where      Expr
	Limit      int // 0 means unset (executor applies a default cap for row output)
}

type parser struct {
	toks []token
	pos  int
}

// Parse parses a query string into a Stmt.
func Parse(q string) (*Stmt, error) {
	toks, err := lex(q)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	return p.parseStmt()
}

func (p *parser) cur() token  { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }

func (p *parser) eatKeyword(kw string) bool {
	t := p.cur()
	if t.kind == tIdent && strings.EqualFold(t.s, kw) {
		p.pos++
		return true
	}
	return false
}

func (p *parser) eatPunct(s string) bool {
	if t := p.cur(); t.kind == tPunct && t.s == s {
		p.pos++
		return true
	}
	return false
}

func perr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", util.ErrCorrupt, fmt.Sprintf(format, a...))
}

func (p *parser) parseStmt() (*Stmt, error) {
	if !p.eatKeyword("select") {
		return nil, perr("expected SELECT")
	}
	st := &Stmt{}
	if err := p.parseSelectList(st); err != nil {
		return nil, err
	}
	if !p.eatKeyword("from") {
		return nil, perr("expected FROM")
	}
	if t := p.next(); t.kind != tIdent { // table name; ignored (one file = one table)
		return nil, perr("expected table name after FROM")
	}
	if p.eatKeyword("where") {
		e, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		st.Where = e
	}
	if p.eatKeyword("limit") {
		t := p.next()
		if t.kind != tNum {
			return nil, perr("expected number after LIMIT")
		}
		n, err := strconv.Atoi(t.s)
		if err != nil || n < 0 {
			return nil, perr("invalid LIMIT %q", t.s)
		}
		st.Limit = n
	}
	if p.cur().kind != tEOF {
		return nil, perr("unexpected token %q", p.cur().s)
	}
	return st, nil
}

func (p *parser) parseSelectList(st *Stmt) error {
	t := p.cur()
	if t.kind == tPunct && t.s == "*" {
		p.pos++
		st.Star = true
		return nil
	}
	if t.kind == tIdent && strings.EqualFold(t.s, "count") {
		p.pos++
		if !p.eatPunct("(") || !p.eatPunct("*") || !p.eatPunct(")") {
			return perr("expected count(*)")
		}
		st.Aggregate = &Agg{Func: "count", Col: "*"}
		return nil
	}
	if t.kind == tIdent && strings.EqualFold(t.s, "top") {
		p.pos++
		if !p.eatPunct("(") {
			return perr("expected ( after top")
		}
		col := p.next()
		if col.kind != tIdent {
			return perr("expected column in top()")
		}
		ag := &Agg{Func: "top", Col: col.s, N: 10}
		if p.eatPunct(",") {
			num := p.next()
			if num.kind != tNum {
				return perr("expected N in top(col, N)")
			}
			n, err := strconv.Atoi(num.s)
			if err != nil || n <= 0 {
				return perr("invalid top N %q", num.s)
			}
			ag.N = n
		}
		if !p.eatPunct(")") {
			return perr("expected ) to close top()")
		}
		st.Aggregate = ag
		return nil
	}
	// Projection: comma-separated identifiers.
	for {
		id := p.next()
		if id.kind != tIdent {
			return perr("expected column name in select list")
		}
		st.Projection = append(st.Projection, id.s)
		if !p.eatPunct(",") {
			break
		}
	}
	return nil
}

func (p *parser) parseExpr() (Expr, error) { return p.parseOr() }

func (p *parser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.eatKeyword("or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = Or{L: left, R: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Expr, error) {
	left, err := p.parseFactor()
	if err != nil {
		return nil, err
	}
	for p.eatKeyword("and") {
		right, err := p.parseFactor()
		if err != nil {
			return nil, err
		}
		left = And{L: left, R: right}
	}
	return left, nil
}

func (p *parser) parseFactor() (Expr, error) {
	if p.eatPunct("(") {
		e, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if !p.eatPunct(")") {
			return nil, perr("expected )")
		}
		return e, nil
	}
	return p.parseCmp()
}

func (p *parser) parseCmp() (Expr, error) {
	col := p.next()
	if col.kind != tIdent {
		return nil, perr("expected column name in predicate")
	}
	// IN list
	if p.eatKeyword("in") {
		if !p.eatPunct("(") {
			return nil, perr("expected ( after IN")
		}
		var vals []string
		for {
			v, err := p.parseValue()
			if err != nil {
				return nil, err
			}
			vals = append(vals, v)
			if p.eatPunct(",") {
				continue
			}
			break
		}
		if !p.eatPunct(")") {
			return nil, perr("expected ) to close IN list")
		}
		return Cmp{Col: col.s, Op: "in", Vals: vals}, nil
	}
	var op string
	switch t := p.next(); {
	case t.kind == tPunct && (t.s == "=" || t.s == "!=" || t.s == "<" || t.s == ">"):
		op = t.s
	default:
		return nil, perr("expected comparison operator after %q", col.s)
	}
	v, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	return Cmp{Col: col.s, Op: op, Vals: []string{v}}, nil
}

func (p *parser) parseValue() (string, error) {
	t := p.next()
	switch t.kind {
	case tStr, tNum:
		return t.s, nil
	default:
		return "", perr("expected value literal")
	}
}
