// Package custom implements YAML-defined custom rules for Aegis.
//
// A custom rule file is YAML:
//
//	rules:
//	  - id: CUSTOM-001
//	    title: "S3 buckets must carry a team tag"
//	    description: "..."
//	    severity: high            # critical|high|medium|low
//	    resource_types: [aws_s3_bucket]
//	    match: all                # all|any — how conditions combine (default all)
//	    conditions:
//	      - attribute: tags.Team
//	        operator: absent      # absent|present|equals|not_equals|contains|regex|gt|lt
//	        value: platform        # required for equals|not_equals|contains|regex|gt|lt
//
// Conditions are violation predicates: when they evaluate true (under the
// match combinator), the rule emits a finding. Nested attributes use dot
// notation (tags.Team, versioning.enabled); nested blocks are traversed
// through their first element deterministically.
//
// Safety contract (same as built-in rules): unknown attribute values never
// produce findings; malformed YAML or invalid specs return descriptive
// errors; nothing here panics.
package custom

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"aegis/internal/ir"

	"gopkg.in/yaml.v3"
)

// Operators supported in conditions.
const (
	opAbsent   = "absent"
	opPresent  = "present"
	opEquals   = "equals"
	opNotEqual = "not_equals"
	opContains = "contains"
	opRegex    = "regex"
	opGT       = "gt"
	opLT       = "lt"
)

var validOperators = map[string]bool{
	opAbsent: true, opPresent: true, opEquals: true, opNotEqual: true,
	opContains: true, opRegex: true, opGT: true, opLT: true,
}

// valueOperators require a `value:` in the condition.
var valueOperators = map[string]bool{
	opEquals: true, opNotEqual: true, opContains: true,
	opRegex: true, opGT: true, opLT: true,
}

// ruleFile is the top-level YAML document.
type ruleFile struct {
	Rules []ruleSpec `yaml:"rules"`
}

// ruleSpec is one rule as written in YAML.
type ruleSpec struct {
	ID            string      `yaml:"id"`
	Title         string      `yaml:"title"`
	Description   string      `yaml:"description"`
	Severity      string      `yaml:"severity"`
	ResourceTypes []string    `yaml:"resource_types"`
	Match         string      `yaml:"match"`
	Conditions    []condition `yaml:"conditions"`
}

// condition is one violation predicate as written in YAML.
type condition struct {
	Attribute string `yaml:"attribute"`
	Operator  string `yaml:"operator"`
	Value     any    `yaml:"value"`
}

// compiledCondition is a validated, ready-to-evaluate condition.
type compiledCondition struct {
	attribute string   // dotted path as written, for evidence
	path      []string // split path
	op        string
	value     string         // normalized string form of Value
	num       float64        // numeric form for gt/lt
	hasNum    bool           // num parsed successfully
	re        *regexp.Regexp // compiled regex for regex
}

// Rule is a compiled custom rule implementing ir.Rule.
type Rule struct {
	id          string
	title       string
	description string
	severity    ir.Severity
	types       map[string]bool
	matchAll    bool
	conds       []compiledCondition
}

func (r *Rule) ID() string          { return r.id }
func (r *Rule) Title() string       { return r.title }
func (r *Rule) Description() string { return r.description }
func (r *Rule) Severity() ir.Severity {
	return r.severity
}

func (r *Rule) AppliesTo(resType string) bool { return r.types[resType] }

// Check evaluates the rule against one resource. Unknown attribute values
// never yield findings.
func (r *Rule) Check(res ir.Resource) (out []ir.Finding) {
	defer func() {
		// Never panic on unexpected resource shapes.
		_ = recover()
	}()
	violated, cond := r.violated(res)
	if !violated {
		return nil
	}
	val, span, present, known := resolvePath(res, cond.path)
	actual := "absent"
	if present {
		if !known {
			return nil // cannot decide — stay silent
		}
		actual = renderValue(val)
		span = val.Span
	}
	if (span == ir.Span{}) {
		span = res.Span
	}
	return []ir.Finding{{
		RuleID:      r.id,
		Title:       r.title,
		Description: r.description,
		Severity:    r.severity,
		Resource:    res.Address(),
		Evidence: ir.Evidence{
			Attribute: cond.attribute,
			Span:      span,
			Actual:    actual,
			Expected:  expectedText(cond),
		},
	}}
}

// violated reports whether the resource violates the rule, and if so the
// first violated condition (conditions evaluated in YAML order for
// determinism).
func (r *Rule) violated(res ir.Resource) (bool, compiledCondition) {
	if r.matchAll {
		var first compiledCondition
		for i, c := range r.conds {
			if !evalCondition(res, c) {
				return false, compiledCondition{}
			}
			if i == 0 {
				first = c
			}
		}
		return true, first
	}
	for _, c := range r.conds {
		if evalCondition(res, c) {
			return true, c
		}
	}
	return false, compiledCondition{}
}

// evalCondition evaluates one violation predicate. Unknown or missing
// values evaluate false (no finding) except for `absent`, which is true
// only when the attribute is genuinely missing.
func evalCondition(res ir.Resource, c compiledCondition) bool {
	val, _, present, known := resolvePath(res, c.path)
	switch c.op {
	case opAbsent:
		return !present
	case opPresent:
		return present && known
	}
	if !present || !known {
		return false
	}
	switch c.op {
	case opEquals:
		s, ok := stringify(val)
		return ok && s == c.value
	case opNotEqual:
		s, ok := stringify(val)
		return ok && s != c.value
	case opContains:
		return containsValue(val, c.value)
	case opRegex:
		s, ok := stringify(val)
		return ok && c.re.MatchString(s)
	case opGT:
		f, ok := toFloat(val)
		return ok && c.hasNum && f > c.num
	case opLT:
		f, ok := toFloat(val)
		return ok && c.hasNum && f < c.num
	}
	return false
}

// resolvePath walks a dotted attribute path through maps and nested blocks.
// Nested blocks ([]Value) are traversed through their first element.
// Returns the value, whether the path exists, and whether it is known.
func resolvePath(res ir.Resource, path []string) (ir.Value, ir.Span, bool, bool) {
	v, ok := res.Attributes[path[0]]
	if !ok {
		return ir.Value{}, ir.Span{}, false, false
	}
	for _, seg := range path[1:] {
		if !v.Known {
			return ir.Value{}, v.Span, true, false
		}
		if m, ok := v.Raw.(map[string]ir.Value); ok {
			v, ok = m[seg]
			if !ok {
				return ir.Value{}, ir.Span{}, false, false
			}
			continue
		}
		if l, ok := v.Raw.([]ir.Value); ok {
			if len(l) == 0 {
				return ir.Value{}, ir.Span{}, false, false
			}
			v = l[0]
			if !v.Known {
				return ir.Value{}, v.Span, true, false
			}
			m, ok := v.Raw.(map[string]ir.Value)
			if !ok {
				return ir.Value{}, ir.Span{}, false, false
			}
			v, ok = m[seg]
			if !ok {
				return ir.Value{}, ir.Span{}, false, false
			}
			continue
		}
		return ir.Value{}, ir.Span{}, false, false
	}
	return v, v.Span, true, v.Known
}

// stringify renders scalar values for comparison.
func stringify(v ir.Value) (string, bool) {
	switch t := v.Raw.(type) {
	case string:
		return t, v.Known
	case bool:
		return strconv.FormatBool(t), v.Known
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), v.Known
	case int:
		return strconv.Itoa(t), v.Known
	case int64:
		return strconv.FormatInt(t, 10), v.Known
	}
	return "", false
}

// renderValue renders a value for evidence Actual.
func renderValue(v ir.Value) string {
	if s, ok := stringify(v); ok {
		if s == "" {
			return "(empty)"
		}
		return s
	}
	if l, ok := v.Raw.([]ir.Value); ok {
		return fmt.Sprintf("(list of %d)", len(l))
	}
	if _, ok := v.Raw.(map[string]ir.Value); ok {
		return "(object)"
	}
	return "(value)"
}

// containsValue reports whether a string contains the needle, or any list
// element's string form contains it.
func containsValue(v ir.Value, needle string) bool {
	if s, ok := stringify(v); ok {
		return strings.Contains(s, needle)
	}
	if l, ok := v.Raw.([]ir.Value); ok && v.Known {
		for _, e := range l {
			if s, ok := stringify(e); ok && strings.Contains(s, needle) {
				return true
			}
		}
	}
	return false
}

// toFloat extracts a numeric value from scalars or numeric strings.
func toFloat(v ir.Value) (float64, bool) {
	switch t := v.Raw.(type) {
	case float64:
		return t, v.Known
	case int:
		return float64(t), v.Known
	case int64:
		return float64(t), v.Known
	case string:
		if !v.Known {
			return 0, false
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	}
	return 0, false
}

// expectedText describes the desired state for evidence.
func expectedText(c compiledCondition) string {
	a := c.attribute
	switch c.op {
	case opAbsent:
		return a + " present"
	case opPresent:
		return a + " absent"
	case opEquals:
		return a + " != " + strconv.Quote(c.value)
	case opNotEqual:
		return a + " == " + strconv.Quote(c.value)
	case opContains:
		return a + " not containing " + strconv.Quote(c.value)
	case opRegex:
		return a + " not matching " + c.value
	case opGT:
		return a + " <= " + c.value
	case opLT:
		return a + " >= " + c.value
	}
	return a + " compliant"
}

// LoadDir loads custom rules from all .yaml/.yml files in dir (sorted by
// file name for determinism). It validates every rule and returns compiled
// ir.Rule values sorted by ID. Any problem returns a descriptive error;
// nothing panics.
func LoadDir(dir string) ([]ir.Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("custom-rules: cannot read directory %q: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("custom-rules: no .yaml/.yml files in %q", dir)
	}
	seen := map[string]string{} // id -> file
	var out []ir.Rule
	for _, f := range files {
		specs, err := loadFile(f)
		if err != nil {
			return nil, err
		}
		for i, s := range specs {
			where := fmt.Sprintf("%s: rules[%d]", f, i)
			r, err := compileSpec(where, s)
			if err != nil {
				return nil, err
			}
			if prev, dup := seen[r.id]; dup {
				return nil, fmt.Errorf("%s: duplicate rule id %q (first defined in %s)", where, r.id, prev)
			}
			seen[r.id] = f
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out, nil
}

// loadFile parses one YAML file into rule specs.
func loadFile(path string) ([]ruleSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("custom-rules: cannot read %q: %w", path, err)
	}
	var doc ruleFile
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // reject unknown fields loudly
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("custom-rules: invalid YAML in %q: %w", path, err)
	}
	if len(doc.Rules) == 0 {
		return nil, fmt.Errorf("custom-rules: %q defines no rules", path)
	}
	return doc.Rules, nil
}

// compileSpec validates one rule spec and compiles it.
func compileSpec(where string, s ruleSpec) (*Rule, error) {
	fail := func(format string, args ...any) (*Rule, error) {
		return nil, fmt.Errorf("%s: %s", where, fmt.Sprintf(format, args...))
	}
	if strings.TrimSpace(s.ID) == "" {
		return fail("rule id is required")
	}
	if strings.TrimSpace(s.Title) == "" {
		return fail("rule %q: title is required", s.ID)
	}
	sev, ok := parseSeverity(s.Severity)
	if !ok {
		return fail("rule %q: invalid severity %q (want critical|high|medium|low)", s.ID, s.Severity)
	}
	if len(s.ResourceTypes) == 0 {
		return fail("rule %q: at least one resource_type is required", s.ID)
	}
	types := map[string]bool{}
	for _, t := range s.ResourceTypes {
		t = strings.TrimSpace(t)
		if t == "" {
			return fail("rule %q: empty resource_type", s.ID)
		}
		types[t] = true
	}
	match := strings.ToLower(strings.TrimSpace(s.Match))
	matchAll := true
	switch match {
	case "", "all":
		matchAll = true
	case "any":
		matchAll = false
	default:
		return fail("rule %q: invalid match %q (want all|any)", s.ID, s.Match)
	}
	if len(s.Conditions) == 0 {
		return fail("rule %q: at least one condition is required", s.ID)
	}
	conds := make([]compiledCondition, 0, len(s.Conditions))
	for i, c := range s.Conditions {
		cc, err := compileCondition(s.ID, i, c)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		conds = append(conds, cc)
	}
	return &Rule{
		id:          s.ID,
		title:       s.Title,
		description: s.Description,
		severity:    sev,
		types:       types,
		matchAll:    matchAll,
		conds:       conds,
	}, nil
}

// compileCondition validates and compiles one condition.
func compileCondition(ruleID string, i int, c condition) (compiledCondition, error) {
	where := fmt.Sprintf("rule %q: condition[%d]", ruleID, i)
	fail := func(format string, args ...any) (compiledCondition, error) {
		return compiledCondition{}, fmt.Errorf("%s: %s", where, fmt.Sprintf(format, args...))
	}
	attr := strings.TrimSpace(c.Attribute)
	if attr == "" {
		return fail("attribute is required")
	}
	var path []string
	for _, seg := range strings.Split(attr, ".") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			return fail("invalid attribute path %q", c.Attribute)
		}
		path = append(path, seg)
	}
	op := strings.ToLower(strings.TrimSpace(c.Operator))
	if !validOperators[op] {
		return fail("invalid operator %q (want absent|present|equals|not_equals|contains|regex|gt|lt)", c.Operator)
	}
	cc := compiledCondition{attribute: attr, path: path, op: op}
	if valueOperators[op] {
		if c.Value == nil {
			return fail("operator %q requires a value", op)
		}
		cc.value = yamlScalarString(c.Value)
		if op == opRegex {
			re, err := regexp.Compile(cc.value)
			if err != nil {
				return fail("invalid regex %q: %v", cc.value, err)
			}
			cc.re = re
		}
		if op == opGT || op == opLT {
			f, err := strconv.ParseFloat(strings.TrimSpace(cc.value), 64)
			if err != nil {
				return fail("operator %q requires a numeric value, got %q", op, cc.value)
			}
			cc.num, cc.hasNum = f, true
		}
	}
	return cc, nil
}

// yamlScalarString normalizes a YAML scalar for comparison.
func yamlScalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return fmt.Sprintf("%v", v)
}

// parseSeverity maps the YAML severity string to ir.Severity.
func parseSeverity(s string) (ir.Severity, bool) {
	switch ir.Severity(strings.ToLower(strings.TrimSpace(s))) {
	case ir.SeverityCritical:
		return ir.SeverityCritical, true
	case ir.SeverityHigh:
		return ir.SeverityHigh, true
	case ir.SeverityMedium:
		return ir.SeverityMedium, true
	case ir.SeverityLow:
		return ir.SeverityLow, true
	}
	return "", false
}
