// Package ir defines Aegis's canonical Infrastructure IR.
//
// Every language adapter (HCL/Terraform, CloudFormation, Kubernetes, ...)
// parses into these types. Every analysis engine (rules, graph, remediation)
// consumes these types. Nothing else crosses the adapter/engine boundary.
//
// Design rules:
//   - Source spans are preserved on every resource and attribute.
//   - Unresolved values are explicit (Value.Known == false), never zero-values
//     pretending to be data.
//   - Findings carry evidence: the exact attribute, span, and actual value.
package ir

import "fmt"

// Severity of a finding, ordered low -> critical.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Span locates a construct in its source file. Lines and columns are 1-based.
type Span struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	StartCol  int    `json:"start_col"`
	EndLine   int    `json:"end_line"`
	EndCol    int    `json:"end_col"`
}

func (s Span) String() string {
	return fmt.Sprintf("%s:%d:%d", s.File, s.StartLine, s.StartCol)
}

// Value is a resolved attribute value. Known == false means the value could
// not be resolved statically (variable, data source, module output, function
// call). Rules must treat unknown values as "cannot decide", not as false.
//
// When the value is an unresolved *reference*, Ref holds its dotted path
// (e.g. "var.region", "local.tags", "data.aws_ami.ubuntu.id") so a later
// semantics pass can resolve it. Known is always false when Ref is set.
type Value struct {
	// Raw holds the Go-native value: bool, string, float64, []Value, map[string]Value.
	Raw   any
	Known bool
	Span  Span
	Ref   string
	// EncodeJSON marks a value that originated from jsonencode() with
	// non-static arguments. The semantics layer resolves the inner structure
	// then JSON-encodes it to a string.
	EncodeJSON bool `json:"-"`
}

// IsRef reports whether this value is an unresolved reference.
func (v Value) IsRef() bool { return v.Ref != "" }

// Helpers to extract typed values safely.
func (v Value) AsBool() (bool, bool) {
	b, ok := v.Raw.(bool)
	return b, v.Known && ok
}

func (v Value) AsString() (string, bool) {
	s, ok := v.Raw.(string)
	return s, v.Known && ok
}

func (v Value) AsList() ([]Value, bool) {
	l, ok := v.Raw.([]Value)
	return l, v.Known && ok
}

func (v Value) AsMap() (map[string]Value, bool) {
	m, ok := v.Raw.(map[string]Value)
	return m, v.Known && ok
}

// UnknownValue builds an explicitly-unresolved value at a span.
func UnknownValue(span Span) Value { return Value{Known: false, Span: span} }

// Resource is one infrastructure object in the canonical model.
type Resource struct {
	// Type is provider-qualified, e.g. "aws_s3_bucket".
	Type string `json:"type"`
	// Name is the Terraform label / logical name, e.g. "app_data".
	Name string `json:"name"`
	// Provider is the inferred provider, e.g. "aws".
	Provider string `json:"provider"`
	// Attributes maps attribute name -> value. Nested blocks are
	// represented as []Value of map[string]Value, or map[string]Value.
	Attributes map[string]Value `json:"-"`
	// Span covers the whole block.
	Span Span `json:"span"`
	// SuppressedRules holds rule IDs suppressed for this resource via
	// inline comments (e.g. `# aegis:skip=AEGIS-AWS-001`). The special
	// value "all" suppresses every rule for the resource. Empty means
	// no suppressions. Populated by adapters; honored by the engine.
	SuppressedRules []string `json:"suppressed_rules,omitempty"`
}

// Attr returns the attribute value and whether the key exists.
func (r Resource) Attr(name string) (Value, bool) {
	v, ok := r.Attributes[name]
	return v, ok
}

// Address returns a Terraform-style address: aws_s3_bucket.app_data.
func (r Resource) Address() string { return r.Type + "." + r.Name }

// Diagnostic is a non-fatal parse/analysis problem. The scanner never fails
// silently: anything it could not understand is reported here.
type Diagnostic struct {
	Level   string `json:"level"` // "error" | "warning"
	Message string `json:"message"`
	Span    Span   `json:"span"`
}

// Evidence backs a finding: which attribute, where, and what value.
type Evidence struct {
	Attribute string `json:"attribute"`
	Span      Span   `json:"span"`
	Actual    string `json:"actual"`
	Expected  string `json:"expected"`
}

// PathStep is one hop in an evidence-backed attack path (Milestone 3).
type PathStep struct {
	Resource string `json:"resource"` // "type.name"
	Detail   string `json:"detail"`   // why this step matters
	Span     Span   `json:"span"`
}

// ComplianceRef maps a finding to a control in a compliance framework,
// e.g. {Framework: "CIS-AWS-1.5", Control: "2.1.1"}.
type ComplianceRef struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
}

// Finding is one rule violation.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Resource    string   `json:"resource"` // Resource.Address()
	Evidence    Evidence `json:"evidence"`
	// Remediation gives concrete fix steps (Terraform snippet). Populated
	// at report time via rules.RemediationFor — rules never set it directly.
	Remediation string `json:"remediation,omitempty"`
	// References lists documentation URLs for this finding. Populated
	// at report time via rules.RemediationFor — rules never set it directly.
	References []string `json:"references,omitempty"`
	// Path, when non-empty, is the evidence-backed attack path: the ordered
	// chain of resources an attacker traverses. Empty for single-resource
	// findings (Milestones 1-2).
	Path []PathStep `json:"path,omitempty"`
	// Compliance lists framework controls this finding violates. Populated
	// at report time via rules.ComplianceFor — rules never set it directly.
	Compliance []ComplianceRef `json:"compliance,omitempty"`
}

// CrossResourceRule is implemented by Milestone 3+ rules that need the full
// resource set: attack paths, trust analysis, reachability. The engine calls
// CheckAll once per scan instead of Check per resource. It must be
// deterministic and never panic; unknown values yield no finding.
type CrossResourceRule interface {
	Rule
	CheckAll(resources []Resource) []Finding
}

// Rule is the interface every check implements. Rules are deterministic:
// the same resources must always produce the same findings.
type Rule interface {
	ID() string
	Title() string
	Description() string
	Severity() Severity
	// AppliesTo reports whether this rule inspects the given resource type.
	// Returning false skips Check entirely.
	AppliesTo(resType string) bool
	// Check inspects one resource and returns findings (possibly empty).
	// It must never panic on unexpected shapes; unknown values yield no finding.
	Check(r Resource) []Finding
}

// Adapter parses source files of one IaC language into IR.
type Adapter interface {
	// Name identifies the adapter, e.g. "terraform".
	Name() string
	// Handles reports whether this adapter parses the given file path.
	Handles(path string) bool
	// Parse converts file content into resources. Diagnostics cover anything
	// the adapter could not represent; hard failures return error.
	Parse(path string, src []byte) ([]Resource, []Diagnostic, error)
}

// ScanResult is the complete output of one scan.
type ScanResult struct {
	Target      string       `json:"target"`
	Resources   int          `json:"resources_scanned"`
	Findings    []Finding    `json:"findings"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}
