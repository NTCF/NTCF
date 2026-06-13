// Package query implements NTCF's SQL-subset search and analytics engine. It
// parses a small, deliberately bounded grammar into an AST, then executes it
// over a store.Reader with predicate pushdown: zone maps and bloom filters
// prune whole segments, inverted bitmap indexes resolve equality predicates to
// row sets without decoding, and only the columns/segments that survive are
// ever decompressed.
//
// Supported grammar (case-insensitive keywords):
//
//	SELECT count(*) | top(col [, N]) | * | col [, col ...]
//	FROM events
//	[WHERE <expr>]
//	[LIMIT n]
//
//	<expr>  := <or>
//	<or>    := <and> (OR <and>)*
//	<and>   := <factor> (AND <factor>)*
//	<factor>:= '(' <expr> ')' | <cmp>
//	<cmp>   := col ('=' | '!=' | '<' | '>') value
//	         | col IN '(' value (',' value)* ')'
//	value   := 'quoted-string' | number
//
// Full SQL (joins, GROUP BY, arbitrary expressions) is a documented roadmap
// item; the subset above covers the search and triage queries the CLI exposes.
package query

import (
	"fmt"
	"strings"

	"github.com/ntcf/ntcf/internal/util"
)

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tNum
	tStr
	tPunct
)

type token struct {
	kind tokKind
	s    string
}

// lex tokenises q. String literals are single-quoted; ” is an escaped quote.
func lex(q string) ([]token, error) {
	var toks []token
	i, n := 0, len(q)
	for i < n {
		c := q[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '\'':
			i++
			var sb strings.Builder
			for i < n {
				if q[i] == '\'' {
					if i+1 < n && q[i+1] == '\'' { // escaped quote
						sb.WriteByte('\'')
						i += 2
						continue
					}
					break
				}
				sb.WriteByte(q[i])
				i++
			}
			if i >= n {
				return nil, fmt.Errorf("%w: unterminated string literal", util.ErrCorrupt)
			}
			i++ // closing quote
			toks = append(toks, token{tStr, sb.String()})
		case c == '!':
			if i+1 < n && q[i+1] == '=' {
				toks = append(toks, token{tPunct, "!="})
				i += 2
			} else {
				return nil, fmt.Errorf("%w: unexpected '!'", util.ErrCorrupt)
			}
		case c == '=' || c == '<' || c == '>' || c == '(' || c == ')' || c == ',' || c == '*':
			toks = append(toks, token{tPunct, string(c)})
			i++
		case isDigit(c):
			start := i
			for i < n && (isDigit(q[i]) || q[i] == '.') {
				i++
			}
			toks = append(toks, token{tNum, q[start:i]})
		case isIdentStart(c):
			start := i
			for i < n && isIdentPart(q[i]) {
				i++
			}
			toks = append(toks, token{tIdent, q[start:i]})
		default:
			return nil, fmt.Errorf("%w: unexpected character %q", util.ErrCorrupt, string(c))
		}
	}
	toks = append(toks, token{tEOF, ""})
	return toks, nil
}

func isDigit(c byte) bool      { return c >= '0' && c <= '9' }
func isIdentStart(c byte) bool { return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isIdentPart(c byte) bool  { return isIdentStart(c) || isDigit(c) || c == '.' }
