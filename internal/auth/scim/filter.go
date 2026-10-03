package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// A small SCIM filter (RFC 7644 §3.4.2.2) parser for the subset IdPs send:
// "eq" and "pr" comparisons joined by "and", parentheses, value-path filters
// (emails[type eq "work"]) with an optional sub-attribute
// (emails[type eq "work"].value eq "x"), and dotted sub-attributes
// (name.givenName, emails.value). Attribute names and operators are
// case-insensitive; the core schema URN prefix is accepted and dropped.
// Anything else ("or", "not", other operators) is invalidFilter.

// errInvalidFilter wraps every parse failure.
var errInvalidFilter = errors.New("invalid filter")

const (
	maxFilterLen   = 2048
	maxFilterDepth = 8
)

// Filter is a conjunction of conditions.
type Filter struct {
	And []Cond
}

// Cond is one condition.
type Cond struct {
	// Group is a parenthesised sub-filter (everything else is unset).
	Group *Filter
	// Path is the lower-cased attribute path: ["username"],
	// ["name", "givenname"], ["emails"].
	Path []string
	// Sub is a value-path filter applied to each element of Path.
	Sub *Filter
	// SubAttr is the lower-cased attribute after "]." ("" for none).
	SubAttr string
	// Op is "eq", "pr", or "" for a bare value-path filter.
	Op string
	// Value is the comparison value: string, bool, float64 or nil.
	Value any
}

// schemaPrefixes are dropped from attribute names (lower-case).
var schemaPrefixes = []string{
	strings.ToLower(SchemaUser) + ":",
	strings.ToLower(SchemaGroup) + ":",
	strings.ToLower(SchemaEnterpriseUser) + ":",
}

type tokKind int

const (
	tkEOF tokKind = iota
	tkIdent
	tkString
	tkLParen
	tkRParen
	tkLBracket
	tkRBracket
)

type token struct {
	kind tokKind
	text string // ident text or decoded string
}

func filterErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errInvalidFilter, fmt.Sprintf(format, args...))
}

func tokenize(s string) ([]token, error) {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, token{kind: tkLParen})
			i++
		case c == ')':
			out = append(out, token{kind: tkRParen})
			i++
		case c == '[':
			out = append(out, token{kind: tkLBracket})
			i++
		case c == ']':
			out = append(out, token{kind: tkRBracket})
			i++
		case c == '"':
			j := i + 1
			for ; j < len(s); j++ {
				if s[j] == '\\' {
					j++
					continue
				}
				if s[j] == '"' {
					break
				}
			}
			if j >= len(s) {
				return nil, filterErr("unterminated string")
			}
			var v string
			if err := json.Unmarshal([]byte(s[i:j+1]), &v); err != nil {
				return nil, filterErr("malformed string")
			}
			out = append(out, token{kind: tkString, text: v})
			i = j + 1
		case isIdentChar(c):
			j := i
			for j < len(s) && isIdentChar(s[j]) {
				j++
			}
			out = append(out, token{kind: tkIdent, text: s[i:j]})
			i = j
		default:
			return nil, filterErr("unexpected character %q", c)
		}
	}
	return append(out, token{kind: tkEOF}), nil
}

func isIdentChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '.' || c == ':' || c == '_' || c == '-' || c == '$' || c == '+'
}

type parser struct {
	toks  []token
	pos   int
	depth int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != tkEOF {
		p.pos++
	}
	return t
}

// ParseFilter parses a filter expression.
func ParseFilter(s string) (*Filter, error) {
	if strings.TrimSpace(s) == "" {
		return nil, filterErr("empty filter")
	}
	if len(s) > maxFilterLen {
		return nil, filterErr("filter too long")
	}
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	f, err := p.filter()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tkEOF {
		return nil, filterErr("unexpected %q", t.text)
	}
	return f, nil
}

func (p *parser) filter() (*Filter, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxFilterDepth {
		return nil, filterErr("filter nested too deeply")
	}
	f := &Filter{}
	for {
		c, err := p.cond()
		if err != nil {
			return nil, err
		}
		f.And = append(f.And, c)
		t := p.peek()
		if t.kind != tkIdent {
			return f, nil
		}
		switch strings.ToLower(t.text) {
		case "and":
			p.next()
		case "or":
			return nil, filterErr(`"or" is not supported`)
		default:
			return nil, filterErr("unexpected %q", t.text)
		}
	}
}

func (p *parser) cond() (Cond, error) {
	t := p.next()
	switch t.kind {
	case tkLParen:
		g, err := p.filter()
		if err != nil {
			return Cond{}, err
		}
		if p.next().kind != tkRParen {
			return Cond{}, filterErr("missing )")
		}
		return Cond{Group: g}, nil
	case tkIdent:
	default:
		return Cond{}, filterErr("expected an attribute name")
	}
	if strings.EqualFold(t.text, "not") {
		return Cond{}, filterErr(`"not" is not supported`)
	}
	path, err := attrPath(t.text)
	if err != nil {
		return Cond{}, err
	}
	c := Cond{Path: path}
	if p.peek().kind == tkLBracket {
		p.next()
		sub, err := p.filter()
		if err != nil {
			return Cond{}, err
		}
		if p.next().kind != tkRBracket {
			return Cond{}, filterErr("missing ]")
		}
		c.Sub = sub
		if nt := p.peek(); nt.kind == tkIdent && strings.HasPrefix(nt.text, ".") {
			p.next()
			sa := strings.ToLower(strings.TrimPrefix(nt.text, "."))
			if sa == "" || strings.ContainsAny(sa, ".:") {
				return Cond{}, filterErr("malformed sub-attribute")
			}
			c.SubAttr = sa
		} else {
			// A bare value-path filter: emails[type eq "work"].
			return c, nil
		}
	}
	opTok := p.next()
	if opTok.kind != tkIdent {
		return Cond{}, filterErr("expected an operator")
	}
	switch op := strings.ToLower(opTok.text); op {
	case "eq":
		c.Op = op
		v, err := p.value()
		if err != nil {
			return Cond{}, err
		}
		c.Value = v
	case "pr":
		c.Op = op
	case "ne", "co", "sw", "ew", "gt", "ge", "lt", "le":
		return Cond{}, filterErr("operator %q is not supported", op)
	default:
		return Cond{}, filterErr("unknown operator %q", opTok.text)
	}
	return c, nil
}

func (p *parser) value() (any, error) {
	t := p.next()
	switch t.kind {
	case tkString:
		return t.text, nil
	case tkIdent:
		switch strings.ToLower(t.text) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "null":
			return nil, nil
		}
		if f, err := strconv.ParseFloat(t.text, 64); err == nil {
			return f, nil
		}
	}
	return nil, filterErr("expected a value")
}

// attrPath lower-cases name, drops a schema URN prefix and splits it on
// dots.
func attrPath(name string) ([]string, error) {
	n := strings.ToLower(name)
	for _, pre := range schemaPrefixes {
		if strings.HasPrefix(n, pre) {
			n = n[len(pre):]
			break
		}
	}
	if n == "" || strings.HasPrefix(n, ".") || strings.Contains(n, ":") {
		return nil, filterErr("unknown attribute %q", name)
	}
	parts := strings.Split(n, ".")
	if len(parts) > 2 {
		return nil, filterErr("unknown attribute %q", name)
	}
	for _, s := range parts {
		if s == "" {
			return nil, filterErr("malformed attribute %q", name)
		}
	}
	return parts, nil
}

// --- Evaluation --------------------------------------------------------------

// caseExact lists the attributes compared case-sensitively (RFC 7643: id
// and externalId are caseExact; userName, emails and displayName are not).
var caseExact = map[string]bool{"id": true, "externalid": true}

// Match reports whether resource (a JSON-shaped map) satisfies f.
func (f *Filter) Match(resource map[string]any) bool {
	for _, c := range f.And {
		if !c.match(resource) {
			return false
		}
	}
	return true
}

func (c Cond) match(res map[string]any) bool {
	if c.Group != nil {
		return c.Group.Match(res)
	}
	vals := lookup(res, c.Path)
	if c.Sub != nil {
		var picked []any
		for _, v := range vals {
			if m, ok := v.(map[string]any); ok && c.Sub.Match(m) {
				picked = append(picked, m)
			}
		}
		if c.SubAttr == "" {
			return len(picked) > 0
		}
		vals = nil
		for _, m := range picked {
			vals = append(vals, lookup(m.(map[string]any), []string{c.SubAttr})...)
		}
	}
	exact := c.SubAttr == "" && len(c.Path) == 1 && caseExact[c.Path[0]]
	switch c.Op {
	case "pr":
		for _, v := range vals {
			if present(v) {
				return true
			}
		}
		return false
	case "eq":
		for _, v := range vals {
			if equal(v, c.Value, exact) {
				return true
			}
		}
		if c.Value == nil {
			return len(vals) == 0
		}
	}
	return false
}

// lookup returns the values at path, flattening multi-valued attributes.
func lookup(node map[string]any, path []string) []any {
	cur := []any{node}
	for _, key := range path {
		var nextVals []any
		for _, n := range cur {
			m, ok := n.(map[string]any)
			if !ok {
				continue
			}
			for k, v := range m {
				if !strings.EqualFold(k, key) {
					continue
				}
				if arr, ok := v.([]any); ok {
					nextVals = append(nextVals, arr...)
				} else if v != nil {
					nextVals = append(nextVals, v)
				}
			}
		}
		cur = nextVals
	}
	return cur
}

func present(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func equal(have, want any, exact bool) bool {
	switch w := want.(type) {
	case string:
		h, ok := have.(string)
		if !ok {
			if b, isBool := have.(bool); isBool {
				return strings.EqualFold(w, strconv.FormatBool(b))
			}
			return false
		}
		if exact {
			return h == w
		}
		return strings.EqualFold(h, w)
	case bool:
		switch h := have.(type) {
		case bool:
			return h == w
		case string:
			return strings.EqualFold(h, strconv.FormatBool(w))
		}
	case float64:
		switch h := have.(type) {
		case float64:
			return h == w
		case int:
			return float64(h) == w
		}
	}
	return false
}

// ParsePath parses a PATCH path (RFC 7644 §3.5.2): an attribute path,
// optionally with a value filter and a sub-attribute
// (emails[type eq "work"].value). The returned Cond has no operator.
func ParsePath(s string) (Cond, error) {
	if len(s) > maxFilterLen {
		return Cond{}, filterErr("path too long")
	}
	toks, err := tokenize(s)
	if err != nil {
		return Cond{}, err
	}
	p := &parser{toks: toks}
	t := p.next()
	if t.kind != tkIdent {
		return Cond{}, filterErr("expected an attribute name")
	}
	c := Cond{}
	if c.Path, err = attrPath(t.text); err != nil {
		return Cond{}, err
	}
	if p.peek().kind == tkLBracket {
		p.next()
		if c.Sub, err = p.filter(); err != nil {
			return Cond{}, err
		}
		if p.next().kind != tkRBracket {
			return Cond{}, filterErr("missing ]")
		}
		if nt := p.peek(); nt.kind == tkIdent && strings.HasPrefix(nt.text, ".") {
			p.next()
			c.SubAttr = strings.ToLower(strings.TrimPrefix(nt.text, "."))
			if c.SubAttr == "" || strings.ContainsAny(c.SubAttr, ".:") {
				return Cond{}, filterErr("malformed sub-attribute")
			}
		}
	}
	if p.peek().kind != tkEOF {
		return Cond{}, filterErr("unexpected text after the path")
	}
	return c, nil
}

// isExtensionPath reports whether a PATCH path or attribute key names a
// schema other than the core User/Group one (accepted and ignored).
func isExtensionPath(s string) bool {
	ls := strings.ToLower(strings.TrimSpace(s))
	if !strings.HasPrefix(ls, "urn:") {
		return false
	}
	for _, pre := range schemaPrefixes[:2] {
		if strings.HasPrefix(ls, pre) {
			return false
		}
	}
	return true
}
