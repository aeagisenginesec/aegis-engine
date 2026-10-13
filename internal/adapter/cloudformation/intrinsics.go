package cloudformation

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"aegis/internal/ir"
)

// resolveValue converts a YAML node (a CFN property value) into an ir.Value,
// resolving intrinsic functions where statically possible. Anything that
// cannot be resolved becomes UnknownValue with a Ref describing what it
// was — never a guessed value.
func (t *template) resolveValue(n *yaml.Node) ir.Value {
	span := nodeSpan(t.path, n)
	// YAML tag shorthand: !Ref, !Join, !Sub, !GetAtt, ...
	if len(n.Tag) > 1 && n.Tag[0] == '!' && n.Tag[1] != '!' {
		if v, ok := t.resolveTag(n.Tag[1:], n, span); ok {
			return v
		}
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return scalarValue(t.path, n)
	case yaml.SequenceNode:
		out := make([]ir.Value, 0, len(n.Content))
		for _, item := range n.Content {
			out = append(out, t.resolveValue(item))
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case yaml.MappingNode:
		if len(n.Content) == 2 && n.Content[0].Kind == yaml.ScalarNode {
			if v, ok := t.resolveIntrinsic(n.Content[0].Value, n.Content[1], span); ok {
				return v
			}
		}
		// Plain map (or unresolvable intrinsic shape): convert generically.
		// Check first whether it *looks* like an intrinsic we don't handle.
		if len(n.Content) == 2 && n.Content[0].Kind == yaml.ScalarNode {
			if isIntrinsicKey(n.Content[0].Value) {
				return unknownRef(span, "cfn.intrinsic."+n.Content[0].Value)
			}
		}
		m := map[string]ir.Value{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				continue
			}
			m[snakeCase(k.Value)] = t.resolveValue(n.Content[i+1])
		}
		return ir.Value{Raw: m, Known: true, Span: span}
	case yaml.AliasNode:
		if n.Alias == nil {
			return ir.UnknownValue(span)
		}
		// Cycle guard: an anchor whose subtree aliases itself
		// (&a [*a]) would otherwise recurse until stack overflow.
		if t.aliasActive[n.Alias] {
			t.diags = append(t.diags, ir.Diagnostic{
				Level:   "warning",
				Message: "cloudformation: YAML alias cycle detected; value treated as unknown",
				Span:    span,
			})
			return ir.UnknownValue(span)
		}
		// Expansion budget: nested aliases amplify exponentially
		// (billion laughs). Stop expanding, keep everything parsed
		// so far, and warn once.
		if t.aliasBudget <= 0 {
			if !t.budgetWarned {
				t.budgetWarned = true
				t.diags = append(t.diags, ir.Diagnostic{
					Level:   "warning",
					Message: "cloudformation: YAML alias expansion budget exceeded; remaining alias values treated as unknown",
					Span:    span,
				})
			}
			return ir.UnknownValue(span)
		}
		t.aliasBudget--
		if t.aliasActive == nil {
			t.aliasActive = map[*yaml.Node]bool{}
		}
		t.aliasActive[n.Alias] = true
		v := t.resolveValue(n.Alias)
		delete(t.aliasActive, n.Alias)
		return v
	default:
		return ir.UnknownValue(span)
	}
}

func unknownRef(span ir.Span, ref string) ir.Value {
	return ir.Value{Known: false, Span: span, Ref: ref}
}

// resolveTag handles YAML tag shorthand (!Ref X, !Join [...], !Sub ...).
// The second return reports whether the tag was a CFN intrinsic.
func (t *template) resolveTag(tag string, n *yaml.Node, span ir.Span) (ir.Value, bool) {
	switch tag {
	case "Ref":
		if n.Kind != yaml.ScalarNode {
			return unknownRef(span, "cfn.ref"), true
		}
		return t.resolveRef(n.Value, span), true
	case "GetAtt":
		return t.resolveIntrinsic("Fn::GetAtt", n, span)
	case "Join":
		return t.resolveIntrinsic("Fn::Join", n, span)
	case "Sub":
		return t.resolveIntrinsic("Fn::Sub", n, span)
	case "If":
		return t.resolveIntrinsic("Fn::If", n, span)
	case "ImportValue":
		return t.resolveIntrinsic("Fn::ImportValue", n, span)
	case "FindInMap":
		return t.resolveIntrinsic("Fn::FindInMap", n, span)
	case "Select":
		return t.resolveIntrinsic("Fn::Select", n, span)
	case "Split":
		return t.resolveIntrinsic("Fn::Split", n, span)
	case "GetAZs":
		return t.resolveIntrinsic("Fn::GetAZs", n, span)
	case "Base64":
		// Return the inner value; base64-encoding is a transport detail.
		inner := t.resolveValue(innerNode(n))
		if s, ok := inner.AsString(); ok {
			return ir.Value{Raw: s, Known: true, Span: span}, true
		}
		return unknownRef(span, "cfn.base64"), true
	}
	return ir.Value{}, false
}

// innerNode unwraps a tagged node to its content for tag passthrough.
func innerNode(n *yaml.Node) *yaml.Node {
	// Build a shallow copy without the custom tag so resolveValue
	// processes the content normally.
	c := *n
	c.Tag = ""
	return &c
}

// isIntrinsicKey reports whether a single-key mapping looks like a CFN
// intrinsic function.
func isIntrinsicKey(k string) bool {
	if k == "Ref" {
		return true
	}
	return strings.HasPrefix(k, "Fn::")
}

// resolveIntrinsic handles a single-key mapping {Key: arg}. The second
// return value reports whether the key was an intrinsic at all.
func (t *template) resolveIntrinsic(key string, arg *yaml.Node, span ir.Span) (ir.Value, bool) {
	switch key {
	case "Ref":
		if arg.Kind != yaml.ScalarNode {
			return unknownRef(span, "cfn.ref"), true
		}
		return t.resolveRef(arg.Value, span), true
	case "Fn::GetAtt":
		// Form: [logicalId, attr] or "logicalId.attr".
		var id, attr string
		if arg.Kind == yaml.SequenceNode && len(arg.Content) >= 2 {
			id, attr = scalarText(arg.Content[0]), scalarText(arg.Content[1])
		} else if arg.Kind == yaml.ScalarNode {
			parts := strings.SplitN(arg.Value, ".", 2)
			id = parts[0]
			if len(parts) == 2 {
				attr = parts[1]
			}
		}
		if id == "" {
			return unknownRef(span, "cfn.getatt"), true
		}
		return unknownRef(span, "cfn.getatt."+id+"."+attr), true
	case "Fn::Join":
		if arg.Kind != yaml.SequenceNode || len(arg.Content) != 2 {
			return unknownRef(span, "cfn.join"), true
		}
		delim, ok := t.resolveString(arg.Content[0])
		if !ok {
			return unknownRef(span, "cfn.join"), true
		}
		parts := arg.Content[1]
		if parts.Kind != yaml.SequenceNode {
			return unknownRef(span, "cfn.join"), true
		}
		var sb strings.Builder
		for i, p := range parts.Content {
			s, ok := t.resolveString(p)
			if !ok {
				return unknownRef(span, "cfn.join"), true
			}
			if i > 0 {
				sb.WriteString(delim)
			}
			sb.WriteString(s)
		}
		return ir.Value{Raw: sb.String(), Known: true, Span: span}, true
	case "Fn::Sub":
		return t.resolveSub(arg, span), true
	case "Fn::If", "Fn::ImportValue", "Fn::FindInMap", "Fn::Select",
		"Fn::Split", "Fn::GetAZs", "Fn::Transform", "Fn::ToJsonString":
		return unknownRef(span, "cfn.intrinsic."+key), true
	}
	return ir.Value{}, false
}

// resolveRef handles {Ref: name}.
func (t *template) resolveRef(name string, span ir.Span) ir.Value {
	// Pseudo-parameters.
	if strings.HasPrefix(name, "AWS::") {
		return unknownRef(span, "cfn.pseudo."+name)
	}
	// Template parameters.
	if p, ok := t.params[name]; ok {
		if p.def.Known {
			return p.def
		}
		return unknownRef(span, "cfn.parameter."+name)
	}
	// Resource logical ID: reference to the resource itself.
	if _, ok := t.resources[name]; ok {
		return unknownRef(span, "cfn.resource."+name)
	}
	return unknownRef(span, "cfn.ref."+name)
}

// resolveString resolves a node to a string if fully static.
func (t *template) resolveString(n *yaml.Node) (string, bool) {
	v := t.resolveValue(n)
	s, ok := v.AsString()
	return s, ok
}

// resolveSub handles Fn::Sub: a string or [string, {var: value}].
func (t *template) resolveSub(arg *yaml.Node, span ir.Span) ir.Value {
	var tmpl string
	vars := map[string]*yaml.Node{}
	switch arg.Kind {
	case yaml.ScalarNode:
		tmpl = arg.Value
	case yaml.SequenceNode:
		if len(arg.Content) == 0 || arg.Content[0].Kind != yaml.ScalarNode {
			return unknownRef(span, "cfn.sub")
		}
		tmpl = arg.Content[0].Value
		if len(arg.Content) > 1 && arg.Content[1].Kind == yaml.MappingNode {
			m := arg.Content[1]
			for i := 0; i+1 < len(m.Content); i += 2 {
				if m.Content[i].Kind == yaml.ScalarNode {
					vars[m.Content[i].Value] = m.Content[i+1]
				}
			}
		}
	default:
		return unknownRef(span, "cfn.sub")
	}
	var sb strings.Builder
	rest := tmpl
	for {
		start := strings.Index(rest, "${")
		if start < 0 {
			sb.WriteString(rest)
			break
		}
		sb.WriteString(rest[:start])
		end := strings.Index(rest[start:], "}")
		if end < 0 {
			return unknownRef(span, "cfn.sub") // unbalanced: give up
		}
		end += start
		expr := rest[start+2 : end]
		rest = rest[end+1:]
		// ${Literal} escapes to ${Literal} without the bang; ${!Lit} too.
		if strings.HasPrefix(expr, "!") {
			sb.WriteString("${" + expr[1:] + "}")
			continue
		}
		val, ok := t.subVar(expr, vars, span)
		if !ok {
			return unknownRef(span, "cfn.sub")
		}
		sb.WriteString(val)
	}
	return ir.Value{Raw: sb.String(), Known: true, Span: span}
}

// subVar resolves one ${...} expression inside Fn::Sub.
func (t *template) subVar(expr string, vars map[string]*yaml.Node, span ir.Span) (string, bool) {
	// Dotted form: ${LogicalId.Attr} or ${MyParam}.
	if vn, ok := vars[expr]; ok {
		return t.resolveString(vn)
	}
	base := expr
	if idx := strings.Index(expr, "."); idx >= 0 {
		base = expr[:idx]
		// Dotted resource attribute: unknown (matches GetAtt handling).
		if _, ok := t.resources[base]; ok {
			return "", false
		}
	}
	if p, ok := t.params[base]; ok {
		if s, ok := p.def.AsString(); ok {
			return s, true
		}
		return "", false
	}
	// Pseudo-parameters like ${AWS::Region}: keep literal-ish? No — unknown.
	return "", false
}

// scalarText returns the scalar text or "".
func scalarText(n *yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}

// jsonString encodes a Go-native structure (from a resolved map) as a JSON
// string value, for policy-document style attributes.
func jsonString(path string, n *yaml.Node, t *template) ir.Value {
	span := nodeSpan(path, n)
	native := yamlToNative(n, t, span)
	if native == nil {
		return unknownRef(span, "cfn.jsonencode")
	}
	b, err := json.Marshal(native)
	if err != nil {
		return unknownRef(span, "cfn.jsonencode")
	}
	return ir.Value{Raw: string(b), Known: true, Span: span}
}

// jsonStringPreserveCase is like jsonString but preserves the original
// YAML key casing. Used for embedded JSON documents (IAM policy documents)
// where key casing is semantically significant and must not be snake_cased.
func jsonStringPreserveCase(path string, n *yaml.Node, t *template) ir.Value {
	span := nodeSpan(path, n)
	native := yamlToNativePreserveCase(n, t, span)
	if native == nil {
		return unknownRef(span, "cfn.jsonencode")
	}
	b, err := json.Marshal(native)
	if err != nil {
		return unknownRef(span, "cfn.jsonencode")
	}
	return ir.Value{Raw: string(b), Known: true, Span: span}
}

// yamlToNativePreserveCase converts a YAML node to Go natives without
// transforming key casing. Returns nil if any part is unresolvable.
func yamlToNativePreserveCase(n *yaml.Node, t *template, span ir.Span) any {
	// Handle intrinsic tags first
	if len(n.Tag) > 1 && n.Tag[0] == '!' && n.Tag[1] != '!' {
		if v, ok := t.resolveTag(n.Tag[1:], n, span); ok {
			if !v.Known {
				return nil
			}
			return valueToNative(v)
		}
	}
	switch n.Kind {
	case yaml.ScalarNode:
		v := scalarValue(t.path, n)
		if !v.Known {
			return nil
		}
		return v.Raw
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, item := range n.Content {
			nv := yamlToNativePreserveCase(item, t, span)
			if nv == nil {
				return nil
			}
			out = append(out, nv)
		}
		return out
	case yaml.MappingNode:
		// Check for intrinsic
		if len(n.Content) == 2 && n.Content[0].Kind == yaml.ScalarNode {
			if v, ok := t.resolveIntrinsic(n.Content[0].Value, n.Content[1], span); ok {
				if !v.Known {
					return nil
				}
				return valueToNative(v)
			}
			if isIntrinsicKey(n.Content[0].Value) {
				return nil
			}
		}
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				continue
			}
			// PRESERVE original key casing (no snakeCase)
			v := yamlToNativePreserveCase(n.Content[i+1], t, span)
			if v == nil {
				return nil
			}
			m[k.Value] = v
		}
		return m
	case yaml.AliasNode:
		if n.Alias != nil {
			return yamlToNativePreserveCase(n.Alias, t, span)
		}
		return nil
	default:
		return nil
	}
}

// yamlToNative converts a YAML node to Go natives, resolving intrinsics.
// Returns nil if any part is unresolvable.
func yamlToNative(n *yaml.Node, t *template, span ir.Span) any {
	v := t.resolveValue(n)
	if !v.Known {
		return nil
	}
	return valueToNative(v)
}

func valueToNative(v ir.Value) any {
	switch r := v.Raw.(type) {
	case map[string]ir.Value:
		m := make(map[string]any, len(r))
		for k, vv := range r {
			m[k] = valueToNative(vv)
		}
		return m
	case []ir.Value:
		l := make([]any, 0, len(r))
		for _, vv := range r {
			l = append(l, valueToNative(vv))
		}
		return l
	default:
		return r
	}
}

// snakeCase converts PascalCase / camelCase to snake_case.
// It handles acronym runs: KMSMasterKeyID -> kms_master_key_id,
// VPCId -> vpc_id, SSEAlgorithm -> sse_algorithm.
func snakeCase(s string) string {
	var sb strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				prev := runes[i-1]
				prevIsLower := prev >= 'a' && prev <= 'z'
				prevIsDigit := prev >= '0' && prev <= '9'
				// Start of acronym run after lowercase/digit: "masterKey" -> "master_key"
				// End of acronym run before lowercase: "KMSMaster" -> "kms_master"
				var nextIsLower bool
				if i+1 < len(runes) {
					n := runes[i+1]
					nextIsLower = n >= 'a' && n <= 'z'
				}
				prevIsUpper := prev >= 'A' && prev <= 'Z'
				if prevIsLower || prevIsDigit || (prevIsUpper && nextIsLower) {
					sb.WriteByte('_')
				}
			}
			sb.WriteRune(r - 'A' + 'a')
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// parseInt / parseFloat helpers for scalarValue.
func parseInt(s string, out *float64) (bool, error) {
	var v int64
	_, err := fmt.Sscanf(s, "%d", &v)
	if err != nil {
		return false, err
	}
	// Reject partial parses like "123abc".
	var check int64
	n, _ := fmt.Sscanf(s, "%d", &check)
	_ = n
	*out = float64(v)
	return true, nil
}

func parseFloat(s string, out *float64) (bool, error) {
	_, err := fmt.Sscanf(s, "%g", out)
	if err != nil {
		return false, err
	}
	return true, nil
}
