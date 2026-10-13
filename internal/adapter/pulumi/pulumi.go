// Package pulumi parses Pulumi YAML programs (Pulumi.yaml) into the canonical IR.
//
// Scope: declarative Pulumi YAML only. Pulumi programs written in
// TypeScript, Python, Go, or .NET require language runtimes and are
// explicitly out of scope; see docs/PULUMI.md.
//
// A Pulumi.yaml program looks like:
//
//	name: my-project
//	runtime: yaml
//	resources:
//	  my-bucket:
//	    type: aws:s3:Bucket
//	    properties:
//	      bucket: my-bucket-name
//	      tags:
//	        env: prod
//
// Resource types are normalized to the Terraform-style canonical types
// consumed by the rule packs (aws:s3:Bucket -> aws_s3_bucket) via
// typemap.go. Property names are converted from camelCase to snake_case
// so rules written against Terraform attribute names keep working.
//
// Safety: parsing never executes anything. Pulumi intrinsic functions
// (fn::*) become explicit Unknown values. `${...}` references resolve
// against variables:/configuration:/resources: when statically known and
// become Unknown-with-Ref otherwise.
package pulumi

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"aegis/internal/ir"
)

// Adapter parses Pulumi.yaml programs into IR resources.
type Adapter struct{}

// New returns a Pulumi adapter.
func New() *Adapter { return &Adapter{} }

// Compile-time check that Adapter satisfies ir.Adapter.
var _ ir.Adapter = Adapter{}

// Name identifies the adapter. It is also reported as the per-file format
// in scan completeness.
func (Adapter) Name() string { return "pulumi" }

// Handles reports whether this adapter parses the given path: only files
// literally named Pulumi.yaml / Pulumi.yml (any case). It must be consulted
// before the manifests adapter, which claims every .yaml file.
func (Adapter) Handles(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return base == "pulumi.yaml" || base == "pulumi.yml"
}

// Parse converts a Pulumi.yaml program into IR resources. A document without
// a resources: section yields no resources and a warning diagnostic.
//
// Two layouts are accepted, because both exist in the wild:
//   - Modern (per the Pulumi YAML reference): resources:, variables:,
//     configuration: (or config:) at the document root.
//   - Legacy/embedded: the same sections nested under template:.
// The template: layout takes effect only when the root has no resources:
// of its own; a document with both is read from the root.
func (Adapter) Parse(path string, src []byte) ([]ir.Resource, []ir.Diagnostic, error) {
	p := &parser{path: path}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		p.diags = append(p.diags, ir.Diagnostic{
			Level:   "error",
			Message: fmt.Sprintf("pulumi: invalid YAML: %v", err),
			Span:    ir.Span{File: path},
		})
		return nil, p.diags, nil
	}
	root := nodeMap(&doc)
	if root == nil {
		p.diags = append(p.diags, ir.Diagnostic{
			Level:   "warning",
			Message: fmt.Sprintf("pulumi: %s is not a Pulumi program (no mapping at document root); skipped", path),
			Span:    ir.Span{File: path},
		})
		return nil, p.diags, nil
	}
	prog := programNode(root)
	if prog != root {
		p.diags = append(p.diags, ir.Diagnostic{
			Level:   "info",
			Message: fmt.Sprintf("pulumi: %s uses the template:-nested program layout", path),
			Span:    ir.Span{File: path},
		})
	}
	p.collectVars(prog)
	resNode := nodeField(prog, "resources")
	if resNode == nil || resNode.Kind != yaml.MappingNode {
		p.diags = append(p.diags, ir.Diagnostic{
			Level:   "warning",
			Message: fmt.Sprintf("pulumi: %s has no resources: section; nothing to scan", path),
			Span:    ir.Span{File: path},
		})
		return nil, p.diags, nil
	}
	var out []ir.Resource
	names := sortedKeys(resNode)
	for _, name := range names {
		rn := nodeField(resNode, name)
		if rn == nil || rn.Kind != yaml.MappingNode {
			p.diags = append(p.diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("pulumi: resource %q is not a mapping; skipped", name),
				Span:    p.spanOf(rn, path),
			})
			continue
		}
		out = append(out, p.resource(name, rn))
	}
	return out, p.diags, nil
}

// parser carries per-parse state.
type parser struct {
	path  string
	diags []ir.Diagnostic
	// vars holds statically-known values from variables: and configuration:
	// (defaults). Secrets and values without defaults are absent (unknown).
	vars map[string]*yaml.Node
	// resourceNames is the set of logical resource names for Ref resolution.
	resourceNames map[string]bool
	// resourceTypes maps logical resource name -> canonical TF type,
	// for qualifying Refs in the type.name.attr form rules expect.
	resourceTypes map[string]string
}

// collectVars indexes variables: and configuration: defaults for ${...}
// reference resolution.
func (p *parser) collectVars(root *yaml.Node) {
	p.vars = map[string]*yaml.Node{}
	p.resourceNames = map[string]bool{}
	p.resourceTypes = map[string]string{}
	if v := nodeField(root, "variables"); v != nil && v.Kind == yaml.MappingNode {
		for _, k := range sortedKeys(v) {
			p.vars[k] = nodeField(v, k)
		}
	}
	collectConfig := func(c *yaml.Node) {
		for _, k := range sortedKeys(c) {
			cn := nodeField(c, k)
			if cn == nil {
				continue
			}
			if cn.Kind == yaml.MappingNode {
				// {type:, default:, secret:} form.
				if d := nodeField(cn, "default"); d != nil {
					p.vars[k] = d
				}
				// secret without default: stays unknown (absent from vars).
			} else {
				p.vars[k] = cn
			}
		}
	}
	if c := nodeField(root, "configuration"); c != nil && c.Kind == yaml.MappingNode {
		collectConfig(c)
	} else if c := nodeField(root, "config"); c != nil && c.Kind == yaml.MappingNode {
		// Modern Pulumi YAML reference uses config: instead of configuration:.
		collectConfig(c)
	}
	if r := nodeField(root, "resources"); r != nil && r.Kind == yaml.MappingNode {
		for _, k := range sortedKeys(r) {
			p.resourceNames[k] = true
			// Record canonical type for Ref qualification.
			if rn := nodeField(r, k); rn != nil {
				if ts := nodeScalar(nodeField(rn, "type")); ts != "" {
					if tfType, _ := normalizeType(ts); tfType != "" {
						p.resourceTypes[k] = tfType
					}
				}
			}
		}
	}
}

// resource converts one named resource entry to an IR resource.
func (p *parser) resource(name string, rn *yaml.Node) ir.Resource {
	span := p.spanOf(rn, p.path)
	typeStr := nodeScalar(nodeField(rn, "type"))
	tfType, provider := normalizeType(typeStr)
	if typeStr != "" && !knownType(typeStr) {
		p.diags = append(p.diags, ir.Diagnostic{
			Level:   "warning",
			Message: fmt.Sprintf("pulumi: resource %q has unmapped type %q; using fallback type %q (some rules may not apply)", name, typeStr, tfType),
			Span:    span,
		})
	}
	attrs := map[string]ir.Value{}
	if props := nodeField(rn, "properties"); props != nil && props.Kind == yaml.MappingNode {
		for _, k := range sortedKeys(props) {
			attrs[toSnake(k)] = p.value(nodeField(props, k), span)
		}
	}
	// options.protect / options.ignoreChanges are metadata, not security
	// signals; they are intentionally not mapped to attributes.
	// Promote nested encryption.requireInfrastructureEncryption for Azure
	// storage accounts (same as ARM adapter).
	if tfType == "azurerm_storage_account" {
		if _, exists := attrs["infrastructure_encryption_enabled"]; !exists {
			if enc, ok := attrs["encryption"]; ok {
				if m, ok := enc.AsMap(); ok {
					for ek, ev := range m {
						if ek == "requireInfrastructureEncryption" || ek == "require_infrastructure_encryption" {
							attrs["infrastructure_encryption_enabled"] = ev
							break
						}
					}
				}
			}
		}
		// Pulumi azure-native property names differ from the Terraform
		// attribute names the rules expect; normalize them.
		renameAttr(attrs, "minimum_tls_version", "min_tls_version")
		renameAttr(attrs, "supports_https_traffic_only", "https_traffic_only_enabled")
		renameAttr(attrs, "allow_shared_key_access", "shared_access_key_enabled")
		renameAttr(attrs, "network_rule_set", "network_rules")
		// publicNetworkAccess is an enum in Pulumi ("Enabled"/"Disabled");
		// the rules expect the boolean public_network_access_enabled.
		if v, ok := attrs["public_network_access"]; ok {
			if s, ok := v.AsString(); ok {
				switch s {
				case "Enabled":
					attrs["public_network_access_enabled"] = ir.Value{Raw: true, Known: true, Span: v.Span}
				case "Disabled":
					attrs["public_network_access_enabled"] = ir.Value{Raw: false, Known: true, Span: v.Span}
				}
			}
			delete(attrs, "public_network_access")
		}
	}
	// Rename securityRules -> security_rule for NSGs (TF attribute name).
	if tfType == "azurerm_network_security_group" {
		if v, ok := attrs["security_rules"]; ok {
			attrs["security_rule"] = v
			delete(attrs, "security_rules")
		}
		// azure-native nests each rule's fields under properties:; the
		// rules read direction/access/source_* at the rule level.
		flattenNestedProperties(attrs, "security_rule")
	}
	// azure-native Key Vault wraps all settings under properties:; the
	// rules read purge_protection_enabled etc. at the resource level.
	if tfType == "azurerm_key_vault" {
		flattenNestedProperties(attrs, "")
		renameAttr(attrs, "enable_purge_protection", "purge_protection_enabled")
		renameAttr(attrs, "enable_soft_delete", "soft_delete_enabled")
	}
	// Rename allows -> allow for GCP firewalls (TF attribute name).
	if tfType == "google_compute_firewall" {
		if v, ok := attrs["allows"]; ok {
			attrs["allow"] = v
			delete(attrs, "allows")
		}
	}
	// Convert publicNetworkAccess enum to boolean for MSSQL servers.
	// Pulumi uses public_network_access; TF rules expect public_network_access_enabled.
	if tfType == "azurerm_mssql_server" {
		if v, ok := attrs["public_network_access"]; ok {
			if s, ok := v.AsString(); ok {
				switch s {
				case "Enabled":
					attrs["public_network_access_enabled"] = ir.Value{Raw: true, Known: true, Span: v.Span}
				case "Disabled":
					attrs["public_network_access_enabled"] = ir.Value{Raw: false, Known: true, Span: v.Span}
				}
			}
			delete(attrs, "public_network_access")
		}
	}
	return ir.Resource{
		Type:       tfType,
		Name:       name,
		Provider:   provider,
		Attributes: attrs,
		Span:       span,
	}
}

// value converts a YAML node to an ir.Value. `${...}` strings resolve
// against variables/configuration/resources; fn::* intrinsics and anything
// unresolvable become explicit Unknown values.
func (p *parser) value(n *yaml.Node, span ir.Span) ir.Value {
	if n == nil {
		return ir.UnknownValue(span)
	}
	span = p.spanOf(n, p.path)
	switch n.Kind {
	case yaml.ScalarNode:
		return p.scalar(n, span)
	case yaml.MappingNode:
		// Single-key fn::* mapping = Pulumi intrinsic function call.
		keys := sortedKeys(n)
		if len(keys) == 1 && strings.HasPrefix(keys[0], "fn::") {
			p.diags = append(p.diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("pulumi: intrinsic %q is not statically resolvable; treated as unknown", keys[0]),
				Span:    span,
			})
			return ir.Value{Known: false, Span: span, Ref: keys[0]}
		}
		out := make(map[string]ir.Value, len(keys))
		for _, k := range keys {
			out[toSnake(k)] = p.value(nodeField(n, k), span)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case yaml.SequenceNode:
		out := make([]ir.Value, 0, len(n.Content))
		for _, e := range n.Content {
			out = append(out, p.value(e, span))
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case yaml.AliasNode:
		return p.value(n.Alias, span)
	default:
		return ir.UnknownValue(span)
	}
}

// scalar converts a YAML scalar node. Strings of the form ${name} or
// ${name.attr} are references; everything else is a known scalar.
func (p *parser) scalar(n *yaml.Node, span ir.Span) ir.Value {
	switch n.Tag {
	case "!!null":
		return ir.UnknownValue(span)
	case "!!bool":
		return ir.Value{Raw: n.Value == "true", Known: true, Span: span}
	case "!!int":
		var i int64
		fmt.Sscanf(n.Value, "%d", &i)
		return ir.Value{Raw: float64(i), Known: true, Span: span}
	case "!!float":
		var f float64
		fmt.Sscanf(n.Value, "%g", &f)
		return ir.Value{Raw: f, Known: true, Span: span}
	default:
		s := n.Value
		if ref, ok := parseRef(s); ok {
			return p.resolveRef(ref, span)
		}
		return ir.Value{Raw: s, Known: true, Span: span}
	}
}

// parseRef reports whether s is a ${...} reference and returns its body.
func parseRef(s string) (string, bool) {
	if len(s) > 3 && strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		return s[2 : len(s)-1], true
	}
	return "", false
}

// resolveRef resolves a ${name} or ${name.attr.path} reference against
// variables, configuration defaults, and resource names.
func (p *parser) resolveRef(ref string, span ir.Span) ir.Value {
	head := ref
	if i := strings.Index(head, "."); i >= 0 {
		head = head[:i]
	}
	if v, ok := p.vars[head]; ok {
		// Statically-known variable/config value: inline it.
		return p.value(v, span)
	}
	if p.resourceNames[head] {
		// Qualify with canonical type for cross-adapter Ref compatibility:
		// "logBucket.id" -> "aws_s3_bucket.logBucket.id"
		if tfType, ok := p.resourceTypes[head]; ok && tfType != "" {
			return ir.Value{Known: false, Span: span, Ref: tfType + "." + ref}
		}
		return ir.Value{Known: false, Span: span, Ref: ref}
	}
	// Unknown name: explicit unknown with the ref recorded.
	return ir.Value{Known: false, Span: span, Ref: ref}
}

// spanOf builds an ir.Span from a YAML node's line info.
func (p *parser) spanOf(n *yaml.Node, path string) ir.Span {
	if n == nil {
		return ir.Span{File: path, StartLine: 1, StartCol: 1}
	}
	return ir.Span{File: path, StartLine: n.Line, StartCol: n.Column}
}

// programNode resolves which mapping holds the Pulumi program sections
// (resources:, variables:, configuration:/config:). The modern layout puts
// them at the document root; the legacy layout nests them under template:.
// The template layout applies only when the root defines no resources: of
// its own, so a mixed document is read from the root.
func programNode(root *yaml.Node) *yaml.Node {
	if nodeField(root, "resources") != nil {
		return root
	}
	if t := nodeField(root, "template"); t != nil && t.Kind == yaml.MappingNode {
		return t
	}
	return root
}

// flattenNestedProperties merges nested "properties" maps up one level.
// When attr is "", the resource's own attrs["properties"] map is merged
// into attrs. When attr names a list attribute (e.g. "security_rule"),
// each list entry's nested "properties" map is merged into that entry.
// This normalizes the azure-native API shape (which nests settings under
// properties:) to the flat Terraform attribute layout the rules expect.
// Keys are already snake_cased by value(); existing keys win on conflict.
func flattenNestedProperties(attrs map[string]ir.Value, attr string) {
	merge := func(dst map[string]ir.Value, v ir.Value) {
		if m, ok := v.AsMap(); ok {
			if props, ok := m["properties"]; ok {
				if pm, ok := props.AsMap(); ok {
					for k, pv := range pm {
						if _, exists := dst[k]; !exists {
							dst[k] = pv
						}
					}
				}
			}
		}
	}
	if attr == "" {
		if v, ok := attrs["properties"]; ok {
			if m, ok := v.AsMap(); ok {
				for k, pv := range m {
					if _, exists := attrs[k]; !exists {
						attrs[k] = pv
					}
				}
			}
			delete(attrs, "properties")
		}
		return
	}
	if v, ok := attrs[attr]; ok {
		if lst, ok := v.Raw.([]ir.Value); ok {
			for i := range lst {
				if m, ok := lst[i].AsMap(); ok {
					merge(m, lst[i])
					if _, has := m["properties"]; has {
						delete(m, "properties")
					}
				}
			}
		} else {
			merge(attrs, v)
		}
	}
}

// renameAttr moves attrs[from] to attrs[to] when present and to is absent.
// Used to normalize Pulumi-native property names to the Terraform attribute
// names the rule packs expect.
func renameAttr(attrs map[string]ir.Value, from, to string) {
	if v, ok := attrs[from]; ok {
		if _, exists := attrs[to]; !exists {
			attrs[to] = v
		}
		delete(attrs, from)
	}
}

// nodeMap returns the document's root mapping node, unwrapping the
// top-level DocumentNode.
func nodeMap(doc *yaml.Node) *yaml.Node {
	n := doc
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n.Kind == yaml.MappingNode {
		return n
	}
	return nil
}

// nodeField returns the value node for key k in mapping m, or nil.
func nodeField(m *yaml.Node, k string) *yaml.Node {
	n := m
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == k {
			return n.Content[i+1]
		}
	}
	return nil
}

// sortedKeys returns the mapping's keys in sorted order for determinism.
func sortedKeys(m *yaml.Node) []string {
	n := m
	keys := make([]string, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		keys = append(keys, n.Content[i].Value)
	}
	sort.Strings(keys)
	return keys
}

// nodeScalar returns the scalar string value of n, or "".
func nodeScalar(n *yaml.Node) string {
	if n != nil && n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}

// toSnake converts camelCase (and SCREAMING keys) to snake_case.
// Already-snake names pass through unchanged.
func toSnake(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	runes := []rune(s)
	for i, r := range runes {
		if !unicode.IsUpper(r) {
			b.WriteRune(r)
			continue
		}
		if i > 0 {
			prev := runes[i-1]
			lowerPrev := unicode.IsLower(prev) || unicode.IsDigit(prev)
			lowerNext := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			// Split before an uppercase that starts a new word: either it
			// follows a lowercase/digit (serverSide) or it is the last
			// uppercase before a lowercase run (HTTPServer -> http_server).
			if lowerPrev || lowerNext {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}
