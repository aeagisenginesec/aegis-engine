// Package aws implements the Aegis AWS security rule pack.
//
// Unknown-value contract (hard rule): an attribute that is present but
// unresolved (Value.Known == false, or a shape the adapter produced that we
// cannot interpret) yields NO finding. An attribute that is ABSENT is
// evaluated against the provider's insecure default, which is documented
// per rule. Rules never panic on unexpected shapes.
package aws

import (
	"path/filepath"
	"strings"

	"aegis/internal/ir"
)

// scopeKey returns a directory-scoped identity for companion correlation.
// In Terraform, each directory is an independent module/state: aws_s3_bucket.logs
// in /a/main.tf and /b/main.tf are DIFFERENT buckets. Correlating companions
// (logging, versioning, encryption configs) by bare type.name across directories
// silently suppresses findings when two scanned projects reuse resource names.
// Keying by source directory keeps same-directory cross-file refs working while
// preventing cross-project contamination. Empty span file falls back to the
// bare address (fail-safe: no silent unlinking of resolvable companions).
func scopeKey(r ir.Resource) string {
	if r.Span.File == "" {
		return r.Address()
	}
	return filepath.Dir(r.Span.File) + "\x00" + r.Address()
}

// sameScope reports whether two resources come from the same source directory
// (i.e. the same Terraform module), the unit within which references resolve.
func sameScope(a, b ir.Resource) bool {
	if a.Span.File == "" || b.Span.File == "" {
		return true // cannot determine scope: fail-safe, allow correlation
	}
	return filepath.Dir(a.Span.File) == filepath.Dir(b.Span.File)
}

// getBool classifies a boolean attribute into a tri-state.
// present=false means the attribute key is absent.
// known=false means present but unresolved or not a bool — undecidable.
func getBool(r ir.Resource, name string) (val bool, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return false, ir.Span{}, false, false
	}
	b, kok := v.AsBool()
	return b, v.Span, true, kok
}

// getString classifies a string attribute into a tri-state.
func getString(r ir.Resource, name string) (val string, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return "", ir.Span{}, false, false
	}
	s, kok := v.AsString()
	return s, v.Span, true, kok
}

// getBlocks returns nested blocks for an attribute. Blocks arrive as
// []Value of map[string]Value; a lone map[string]Value is also accepted.
// present=false when the key is absent; known=false when the value is
// unresolved or not a block shape (undecidable — never flag).
func getBlocks(r ir.Resource, name string) (blks []map[string]ir.Value, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return nil, ir.Span{}, false, false
	}
	if !v.Known {
		return nil, v.Span, true, false
	}
	if m, ok := v.AsMap(); ok {
		return []map[string]ir.Value{m}, v.Span, true, true
	}
	l, ok := v.AsList()
	if !ok {
		return nil, v.Span, true, false
	}
	out := make([]map[string]ir.Value, 0, len(l))
	for _, item := range l {
		m, ok := item.AsMap()
		if !ok {
			continue // unexpected shape: skip defensively, never panic
		}
		out = append(out, m)
	}
	return out, v.Span, true, true
}

// blockList extracts a nested block list from a block map (e.g. blk["rule"]).
// Returns nil when the key is absent, unknown, or not a block shape.
func blockList(m map[string]ir.Value, name string) []map[string]ir.Value {
	v, ok := m[name]
	if !ok || !v.Known {
		return nil
	}
	if single, ok := v.AsMap(); ok {
		return []map[string]ir.Value{single}
	}
	l, ok := v.AsList()
	if !ok {
		return nil
	}
	out := make([]map[string]ir.Value, 0, len(l))
	for _, item := range l {
		if bm, ok := item.AsMap(); ok {
			out = append(out, bm)
		}
	}
	return out
}

// blockStrings extracts a list of strings from a block map (e.g. cidr_blocks).
// Returns (values, allKnown): allKnown is false if the list itself or any
// element is unresolved or not a string.
func blockStrings(m map[string]ir.Value, name string) ([]string, bool) {
	v, ok := m[name]
	if !ok {
		return nil, true // absent list: vacuous, treat as known-empty
	}
	if !v.Known {
		return nil, false
	}
	l, ok := v.AsList()
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(l))
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// blockString extracts a single string from a block map.
func blockString(m map[string]ir.Value, name string) (string, ir.Span, bool, bool) {
	v, ok := m[name]
	if !ok {
		return "", ir.Span{}, false, false
	}
	s, kok := v.AsString()
	return s, v.Span, true, kok
}

// blockBool extracts a single bool from a block map (tri-state).
func blockBool(m map[string]ir.Value, name string) (bool, ir.Span, bool, bool) {
	v, ok := m[name]
	if !ok {
		return false, ir.Span{}, false, false
	}
	b, kok := v.AsBool()
	return b, v.Span, true, kok
}

// evidenceSpan prefers the attribute span, falling back to the resource span
// (used when the offending condition is an absent attribute).
func evidenceSpan(attrSpan, resSpan ir.Span) ir.Span {
	if attrSpan.File != "" {
		return attrSpan
	}
	return resSpan
}

// absentInsecureDefault builds the fail-closed finding for an attribute that
// is ABSENT while its provider default is insecure. Absence is decidable —
// the provider documents the default — so unlike an unresolved (unknown)
// value it must fire, never pass silently. actual names the default, e.g.
// "absent (provider default: NONE)".
func absentInsecureDefault(rule ir.Rule, r ir.Resource, attr, actual, expected string) []ir.Finding {
	return []ir.Finding{{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      r.Span, // attribute absent: point at the resource block
			Actual:    actual,
			Expected:  expected,
		},
	}}
}

// findStringFold reports whether any element equals target (case-insensitive,
// trimmed). Used for CIDR matching where adapters may vary whitespace/case.
func findStringFold(haystack []string, target string) bool {
	for _, s := range haystack {
		if strings.EqualFold(strings.TrimSpace(s), target) {
			return true
		}
	}
	return false
}

// companionLinkUncertain reports whether any resource of companionType carries
// a link attribute (linkAttr) that is present but unresolvable: an unknown
// value, or a reference that does not name a resource address (e.g. var.x,
// data.y). Such a companion might cover any parent, so "companion missing"
// findings are undecidable while one exists — the engine must not claim the
// companion is absent. A link that resolves (syntactically or by name) is
// certain and does not count, even when it dangles: a companion aimed at a
// nonexistent parent covers nothing real.
func companionLinkUncertain(resources []ir.Resource, companionType, linkAttr string) bool {
	for _, r := range resources {
		if r.Type != companionType {
			continue
		}
		v, ok := r.Attributes[linkAttr]
		if !ok {
			continue
		}
		if v.IsRef() {
			if _, resOk := refAddrOf(v.Ref); !resOk {
				return true
			}
			continue
		}
		if !v.Known {
			return true
		}
	}
	return false
}

// linkedBucketAddr resolves which aws_s3_bucket a standalone config resource
// (encryption configuration, versioning, logging, etc.) targets via its
// `bucket` attribute: a reference or a known name matched against the bucket
// set. Correlation is directory-scoped: only buckets from the same source
// directory (Terraform module) are candidates, so same-named buckets in
// different scanned projects never cross-contaminate. Unresolvable -> false.
func linkedBucketAddr(r ir.Resource, resources []ir.Resource) (string, bool) {
	v, ok := r.Attributes["bucket"]
	if !ok {
		return "", false
	}
	if v.IsRef() {
		// CloudFormation !Ref to a resource logical ID: "cfn.resource.X".
		// Match by the bucket's Name (its CFN logical ID) in scope.
		if strings.HasPrefix(v.Ref, "cfn.resource.") {
			lid := strings.TrimPrefix(v.Ref, "cfn.resource.")
			for _, b := range resources {
				if b.Type != "aws_s3_bucket" || !sameScope(r, b) {
					continue
				}
				if b.Name == lid {
					return scopeKey(b), true
				}
			}
			return "", false
		}
		addr, ok := refAddrOf(v.Ref)
		if !ok {
			return "", false
		}
		for _, b := range resources {
			if b.Type != "aws_s3_bucket" {
				continue
			}
			if b.Address() == addr && sameScope(r, b) {
				return scopeKey(b), true
			}
		}
		return "", false
	}
	name, ok := v.AsString()
	if !ok {
		return "", false
	}
	name = strings.TrimSpace(name)
	for _, b := range resources {
		if b.Type != "aws_s3_bucket" {
			continue
		}
		if !sameScope(r, b) {
			continue
		}
		if b.Name == name {
			return scopeKey(b), true
		}
		if bn, _, _, known := getString(b, "bucket"); known && strings.TrimSpace(bn) == name {
			return scopeKey(b), true
		}
	}
	return "", false
}

// logDeliveryBuckets returns the set of bucket addresses that serve as the
// target_bucket of an aws_s3_bucket_logging resource. Such buckets are
// logging infrastructure: flagging them for missing hardening (encryption,
// versioning, public-access block, TLS policy, access logging, lifecycle)
// is scanner noise — the security posture that matters is the source
// bucket's. Only definitely-resolved targets are returned; an unresolvable
// target link simply doesn't exempt anything (fail-safe).
func logDeliveryBuckets(resources []ir.Resource) map[string]bool {
	targets := map[string]bool{}
	for _, r := range resources {
		if r.Type != "aws_s3_bucket_logging" {
			continue
		}
		if addr, ok := linkedTargetBucketAddr(r, resources); ok {
			targets[addr] = true
		}
	}
	return targets
}

// linkedTargetBucketAddr resolves the target_bucket attribute of an
// aws_s3_bucket_logging resource to the destination bucket's scoped address.
// Directory-scoped like linkedBucketAddr: a logging config only exempts
// buckets in its own source directory. Used by s3NoAccessLogging to skip
// log-delivery buckets.
func linkedTargetBucketAddr(r ir.Resource, resources []ir.Resource) (string, bool) {
	v, ok := r.Attributes["target_bucket"]
	if !ok {
		return "", false
	}
	if v.IsRef() {
		addr, ok := refAddrOf(v.Ref)
		if !ok {
			return "", false
		}
		for _, b := range resources {
			if b.Type != "aws_s3_bucket" {
				continue
			}
			if b.Address() == addr && sameScope(r, b) {
				return scopeKey(b), true
			}
		}
		return "", false
	}
	name, ok := v.AsString()
	if !ok {
		return "", false
	}
	name = strings.TrimSpace(name)
	for _, b := range resources {
		if b.Type != "aws_s3_bucket" {
			continue
		}
		if !sameScope(r, b) {
			continue
		}
		if b.Name == name {
			return scopeKey(b), true
		}
		if bn, _, _, known := getString(b, "bucket"); known && strings.TrimSpace(bn) == name {
			return scopeKey(b), true
		}
	}
	return "", false
}
