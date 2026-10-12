package aws

import (
	"aegis/internal/ir"
)

// Shared test fixtures for the AWS rule pack.

// spanAt builds a span on line L of test.tf.
func spanAt(line int) ir.Span {
	return ir.Span{File: "test.tf", StartLine: line, StartCol: 1, EndLine: line, EndCol: 20}
}

// kv: known bool value. ks: known string. ku: unknown value.
func kv(b bool, line int) ir.Value { return ir.Value{Raw: b, Known: true, Span: spanAt(line)} }
func ks(s string, line int) ir.Value {
	return ir.Value{Raw: s, Known: true, Span: spanAt(line)}
}
func ku(line int) ir.Value { return ir.Value{Known: false, Span: spanAt(line)} }

// strList builds a known []Value of strings.
func strList(line int, items ...string) ir.Value {
	vals := make([]ir.Value, len(items))
	for i, s := range items {
		vals[i] = ks(s, line)
	}
	return ir.Value{Raw: vals, Known: true, Span: spanAt(line)}
}

// blk builds one nested block: map[string]Value.
func blk(pairs ...any) map[string]ir.Value {
	m := map[string]ir.Value{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = pairs[i+1].(ir.Value)
	}
	return m
}

// blks builds a known block list attribute: []Value of map[string]Value.
func blks(line int, maps ...map[string]ir.Value) ir.Value {
	vals := make([]ir.Value, len(maps))
	for i, m := range maps {
		vals[i] = ir.Value{Raw: m, Known: true, Span: spanAt(line)}
	}
	return ir.Value{Raw: vals, Known: true, Span: spanAt(line)}
}

func res(typ, name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{
		Type:       typ,
		Name:       name,
		Provider:   "aws",
		Attributes: attrs,
		Span:       spanAt(1),
	}
}

// runRule executes a single rule against resources.
func runRule(rule ir.Rule, resources ...ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, r := range resources {
		if rule.AppliesTo(r.Type) {
			out = append(out, rule.Check(r)...)
		}
	}
	return out
}
