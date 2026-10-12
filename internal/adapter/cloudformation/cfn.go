// Package cloudformation implements ir.Adapter for AWS CloudFormation
// templates (JSON and YAML).
//
// Strategy: convert CloudFormation resources into the canonical IR using
// Terraform-style resource types and snake_case attribute names, so the
// entire existing AWS rule pack applies without writing new rules.
//
//   - AWS::S3::Bucket/MyBucket -> ir.Resource{Type: "aws_s3_bucket", Name: "MyBucket"}
//   - PascalCase properties are converted to snake_case recursively.
//   - High-value resources with structural differences (S3, IAM, KMS,
//     Security Groups) get dedicated converters in props.go.
//   - Intrinsic functions (Ref, Fn::GetAtt, Fn::Join, Fn::Sub, ...) are
//     resolved where static; otherwise marked UnknownValue (never guessed).
//   - Parameters without defaults, Mappings, Conditions, and ImportValue
//     are unknown by design.
//
// Detection: Handles() sniffs file content for CloudFormation markers
// (AWSTemplateFormatVersion or Resources: with Type: AWS::*) because the
// manifests adapter claims every .yaml/.yml/.json file. This adapter must
// be registered BEFORE manifests.Adapter in defaultAdapters().
package cloudformation

import (
	"bytes"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"aegis/internal/ir"
)

// Adapter parses CloudFormation templates into the canonical IR.
type Adapter struct{}

// Compile-time check that Adapter satisfies ir.Adapter.
var _ ir.Adapter = Adapter{}

// New constructs the adapter.
func New() *Adapter { return &Adapter{} }

// Name identifies the adapter.
func (Adapter) Name() string { return "cloudformation" }

// planJSONSuffix is excluded: it belongs to the planjson adapter.
const planJSONSuffix = ".plan.json"

// Handles reports whether the file looks like a CloudFormation template.
// Extension gate first (cheap), then content sniffing for CFN markers.
func (Adapter) Handles(path string) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, planJSONSuffix) {
		return false
	}
	switch {
	case strings.HasSuffix(lower, ".yaml"), strings.HasSuffix(lower, ".yml"),
		strings.HasSuffix(lower, ".json"), strings.HasSuffix(lower, ".template"):
		// ok
	default:
		return false
	}
	return looksLikeCFN(path)
}

// looksLikeCFN reads the file and checks for CloudFormation markers.
// Bounded: discovery already caps file size; we additionally cap the sniff.
func looksLikeCFN(path string) bool {
	src, err := readBounded(path, 1<<20) // 1 MiB is plenty for a marker scan
	if err != nil {
		return false
	}
	// Fast path: textual markers.
	if bytes.Contains(src, []byte("AWSTemplateFormatVersion")) {
		return true
	}
	// Structural check: top-level mapping with Resources: containing
	// a Type: AWS::* entry.
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil || len(doc.Content) == 0 {
		return false
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return false
	}
	res := mappingGet(root, "Resources")
	if res == nil || res.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(res.Content); i += 2 {
		def := res.Content[i+1]
		if def.Kind != yaml.MappingNode {
			continue
		}
		t := mappingGet(def, "Type")
		if t != nil && t.Kind == yaml.ScalarNode && strings.HasPrefix(t.Value, "AWS::") {
			return true
		}
	}
	return false
}

// template holds the parsed sections of one CFN template.
type template struct {
	path       string
	params     map[string]paramDef   // Parameters:
	resources  map[string]*yaml.Node // Resources: logicalID -> definition node
	outputs    map[string]*yaml.Node // Outputs: logicalID -> definition node
	diags      []ir.Diagnostic
	converted  map[string]ir.Resource // logicalID -> converted resource (for cross-refs)
	companions []ir.Resource          // synthesized companion resources
}

type paramDef struct {
	def     ir.Value // Default value, or UnknownValue if none
	allowed []string
	node    *yaml.Node
}

// Parse converts a CloudFormation template into IR resources.
func (Adapter) Parse(path string, src []byte) ([]ir.Resource, []ir.Diagnostic, error) {
	t := &template{
		path:      path,
		params:    map[string]paramDef{},
		resources: map[string]*yaml.Node{},
		outputs:   map[string]*yaml.Node{},
		converted: map[string]ir.Resource{},
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, []ir.Diagnostic{{
			Level:   "error",
			Message: "cloudformation: invalid YAML/JSON: " + err.Error(),
			Span:    fileSpan(path),
		}}, nil
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, []ir.Diagnostic{{
			Level:   "warning",
			Message: "cloudformation: top-level mapping not found; skipped",
			Span:    fileSpan(path),
		}}, nil
	}
	root := doc.Content[0]

	t.parseParameters(mappingGet(root, "Parameters"))
	t.parseResources(mappingGet(root, "Resources"))
	t.parseOutputs(mappingGet(root, "Outputs"))
	if m := mappingGet(root, "Mappings"); m != nil {
		t.diags = append(t.diags, ir.Diagnostic{
			Level:   "warning",
			Message: "cloudformation: Mappings are not resolved; Fn::FindInMap values will be unknown",
			Span:    nodeSpan(path, m),
		})
	}

	var out []ir.Resource
	// Convert resources in document order for determinism.
	resNode := mappingGet(root, "Resources")
	if resNode != nil {
		for i := 0; i+1 < len(resNode.Content); i += 2 {
			logicalID := resNode.Content[i].Value
			if r, ok := t.convertResource(logicalID); ok {
				out = append(out, r)
			}
		}
	}
	// Append synthesized companion resources (S3 public-access-block,
	// inline IAM policies, ...).
	out = append(out, t.drainCompanions()...)
	// Synthetic output resources for secret-detection parity with terraform_output.
	outNode := mappingGet(root, "Outputs")
	if outNode != nil {
		for i := 0; i+1 < len(outNode.Content); i += 2 {
			name := outNode.Content[i].Value
			def := outNode.Content[i+1]
			attrs := map[string]ir.Value{}
			if def.Kind == yaml.MappingNode {
				if v := mappingGet(def, "Value"); v != nil {
					attrs["value"] = t.resolveValue(v)
				}
				if d := mappingGet(def, "Description"); d != nil {
					attrs["description"] = scalarValue(path, d)
				}
			}
			out = append(out, ir.Resource{
				Type:       "cfn_output",
				Name:       name,
				Provider:   "cfn",
				Attributes: attrs,
				Span:       nodeSpan(path, def),
			})
		}
	}
	return out, t.diags, nil
}

// parseParameters records template parameters. Defaults become known
// values; parameters without defaults are explicitly unknown.
func (t *template) parseParameters(node *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		name := node.Content[i].Value
		def := node.Content[i+1]
		p := paramDef{node: def, def: ir.UnknownValue(nodeSpan(t.path, def))}
		p.def.Ref = "cfn.parameter." + name
		if def.Kind == yaml.MappingNode {
			if d := mappingGet(def, "Default"); d != nil {
				p.def = scalarValue(t.path, d)
			}
			if a := mappingGet(def, "AllowedValues"); a != nil && a.Kind == yaml.SequenceNode {
				for _, item := range a.Content {
					if item.Kind == yaml.ScalarNode {
						p.allowed = append(p.allowed, item.Value)
					}
				}
			}
		}
		t.params[name] = p
	}
}

// parseResources records resource definition nodes keyed by logical ID.
func (t *template) parseResources(node *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		t.resources[node.Content[i].Value] = node.Content[i+1]
	}
}

// parseOutputs records output definition nodes keyed by logical ID.
func (t *template) parseOutputs(node *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		t.outputs[node.Content[i].Value] = node.Content[i+1]
	}
}

// convertResource converts one CFN resource to IR. Returns false when the
// resource is skipped (with a diagnostic recorded).
func (t *template) convertResource(logicalID string) (ir.Resource, bool) {
	if r, ok := t.converted[logicalID]; ok {
		return r, true
	}
	def, ok := t.resources[logicalID]
	if !ok || def.Kind != yaml.MappingNode {
		return ir.Resource{}, false
	}
	span := nodeSpan(t.path, def)
	typeNode := mappingGet(def, "Type")
	if typeNode == nil || typeNode.Kind != yaml.ScalarNode {
		t.diags = append(t.diags, ir.Diagnostic{
			Level:   "warning",
			Message: "cloudformation: resource " + logicalID + " has no Type; skipped",
			Span:    span,
		})
		return ir.Resource{}, false
	}
	cfnType := typeNode.Value
	tfType, ok := cfnTypeToTF(cfnType)
	if !ok {
		t.diags = append(t.diags, ir.Diagnostic{
			Level:   "warning",
			Message: "cloudformation: unmapped resource type " + cfnType + " (" + logicalID + "); skipped",
			Span:    nodeSpan(t.path, typeNode),
		})
		return ir.Resource{}, false
	}
	// Mark as converted before converting properties so self-references
	// terminate (they resolve to unknown refs anyway).
	t.converted[logicalID] = ir.Resource{Type: tfType, Name: logicalID}

	attrs := map[string]ir.Value{}
	if props := mappingGet(def, "Properties"); props != nil {
		attrs = t.convertProperties(cfnType, tfType, props)
	}

	// Special-case synthesizers may add companion resources (e.g. S3
	// public-access-block, inline IAM policies). They are buffered on the
	// template and drained after the main pass.
	if synth, ok := specialConverters[cfnType]; ok {
		var companions []ir.Resource
		attrs, companions = synth(t, logicalID, tfType, attrs, def)
		t.companions = append(t.companions, companions...)
	}

	r := ir.Resource{
		Type:       tfType,
		Name:       logicalID,
		Provider:   "aws",
		Attributes: attrs,
		Span:       span,
	}
	t.converted[logicalID] = r
	return r, true
}

// drainCompanions returns synthesized companion resources accumulated
// during conversion and clears the buffer.
func (t *template) drainCompanions() []ir.Resource {
	out := t.companions
	t.companions = nil
	return out
}

// readBounded reads a file, capping the bytes read.
func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max+1))
}

// --- yaml.Node helpers ---

func fileSpan(path string) ir.Span {
	return ir.Span{File: path, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1}
}

func nodeSpan(path string, n *yaml.Node) ir.Span {
	if n == nil {
		return fileSpan(path)
	}
	return ir.Span{
		File:      path,
		StartLine: n.Line,
		StartCol:  n.Column,
		EndLine:   n.Line,
		EndCol:    n.Column + len(n.Value),
	}
}

// mappingGet returns the value node for key in a mapping node, or nil.
func mappingGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Kind == yaml.ScalarNode && m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mappingKeys returns the scalar keys of a mapping node.
func mappingKeys(m *yaml.Node) []string {
	var out []string
	if m == nil || m.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Kind == yaml.ScalarNode {
			out = append(out, m.Content[i].Value)
		}
	}
	return out
}

// keyNode returns the key node for key in a mapping node (for spans).
func keyNode(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Kind == yaml.ScalarNode && m.Content[i].Value == key {
			return m.Content[i]
		}
	}
	return nil
}

// scalarValue converts a YAML scalar node to an ir.Value.
func scalarValue(path string, n *yaml.Node) ir.Value {
	span := nodeSpan(path, n)
	switch n.Tag {
	case "!!bool":
		return ir.Value{Raw: n.Value == "true" || n.Value == "True" || n.Value == "TRUE", Known: true, Span: span}
	case "!!int":
		var f float64
		_, err := parseInt(n.Value, &f)
		if err != nil {
			return ir.Value{Raw: n.Value, Known: true, Span: span}
		}
		return ir.Value{Raw: f, Known: true, Span: span}
	case "!!float":
		var f float64
		_, err := parseFloat(n.Value, &f)
		if err != nil {
			return ir.Value{Raw: n.Value, Known: true, Span: span}
		}
		return ir.Value{Raw: f, Known: true, Span: span}
	case "!!null":
		return ir.Value{Raw: nil, Known: true, Span: span}
	default:
		return ir.Value{Raw: n.Value, Known: true, Span: span}
	}
}
