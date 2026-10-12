// Fixers for individual rules. Only unambiguous, safe fixes are automated:
//
//	001 S3 no SSE ............ insert server_side_encryption_configuration block
//	002 S3 public ACL ........ acl = "private" (known public values only)
//	007 RDS storage_encrypted  storage_encrypted = true
//	008 RDS deletion_protection deletion_protection = true
//	009 EBS encrypted ........ encrypted = true
//	010 CloudTrail validation  enable_log_file_validation = true
//	011 RDS publicly_accessible publicly_accessible = false
//	012 S3 no versioning ...... insert versioning { enabled = true }
//
// Deliberately NOT fixed (human judgment required):
//
//	003 bucket policy Principal "*" .. policy rewrite needs review
//	004/005 open CIDR ranges ....... which CIDRs are legitimate is a decision
//	006 wildcard IAM ............... least-privilege scoping needs review
//	101/102/103/104 attack paths ... trust/policy redesign needs review
//
// SAFETY AUDIT (2026-10-11, Phase 4 Workstream 4). Every fixer below was
// audited against three guarantees:
//
// (a) Minimal diff. boolFixer replaces exactly one attribute line via
// attrEdit (which aborts, proposing nothing, unless the evidence span's
// first line really is `name = ...`), or inserts exactly one attribute line
// via insertAttrBeforeClose. blockFixer inserts exactly one nested block via
// insertBeforeClose (which aborts unless the target line really is the
// resource's lone closing brace). Nothing is reformatted, no adjacent lines
// are touched, and no new attribute/block is ever added when one already
// exists.
//
// (b) Patched file re-parses cleanly. ValidatePatch (remediation.go)
// applies every patch to an isolated temp copy and re-scans it: the
// ResourceMissing gate rejects any patch after which the target resource
// no longer parses, and the diagnostics gate rejects any patch that
// introduces new error-level diagnostics. Coverage: TestValidatePatchFixed,
// TestValidatePatchCorruptPatchRejected, TestValidatePatchNewErrorDiagnosticsRejected
// in remediation_test.go, plus per-patch re-parse assertions over a complex
// file in safety_test.go.
//
// (c) IAM policies and security-group ingress rules are never touched. Each
// fixer hard-matches res.Type against aws_s3_bucket/_acl, aws_db_instance,
// aws_ebs_volume, or aws_cloudtrail — no fixer can address any aws_iam_* or
// aws_security_group* / aws_network_acl type, and every Propose first
// checks res.Type (and, for 002, the evidence attribute name and a known
// public value). On top of that, ProposeAll skips findings on blocked
// resource types (safety.go BlockedResourceTypes) unless AllowBlocked is
// set, so even a future fixer matching those types cannot auto-propose.
package remediation

import (
	"fmt"
	"strings"

	"aegis/internal/ir"
)

// publicACLValues mirrors the rule's set of ACL values considered public.
var publicACLValues = map[string]bool{
	"public-read":        true,
	"public-read-write":  true,
	"authenticated-read": true,
}

// attrEdit builds an Edit replacing the evidence span's lines with
// `<indent><name> = <newValue>`. It sanity-checks that the first replaced
// line actually assigns the attribute; otherwise it returns ok=false and
// the caller proposes nothing (never corrupt on a span mismatch).
func attrEdit(src []byte, f ir.Finding, name, newValue string) (Edit, bool) {
	span := f.Evidence.Span
	lines := splitLines(src)
	if span.StartLine < 1 || span.EndLine < span.StartLine || span.EndLine > len(lines) {
		return Edit{}, false
	}
	first := lines[span.StartLine-1]
	trimmed := strings.TrimSpace(first)
	// Expect `name = ...` (allow leading whitespace only).
	if !strings.HasPrefix(trimmed, name) {
		return Edit{}, false
	}
	rest := strings.TrimSpace(trimmed[len(name):])
	if !strings.HasPrefix(rest, "=") {
		return Edit{}, false
	}
	indent := first[:len(first)-len(strings.TrimLeft(first, " \t"))]
	return Edit{
		File:      span.File,
		StartLine: span.StartLine,
		EndLine:   span.EndLine,
		NewText:   indent + name + " = " + newValue,
	}, true
}

// insertBeforeClose builds an Edit inserting blockText (already indented
// relative to the resource body) before the resource's closing brace.
// It verifies the EndLine really is a lone closing brace.
func insertBeforeClose(src []byte, res ir.Resource, blockText string) (Edit, bool) {
	lines := splitLines(src)
	end := res.Span.EndLine
	if end < 1 || end > len(lines) {
		return Edit{}, false
	}
	braceLine := lines[end-1]
	if strings.TrimSpace(braceLine) != "}" {
		return Edit{}, false
	}
	if res.Span.File == "" {
		return Edit{}, false
	}
	braceIndent := braceLine[:len(braceLine)-len(strings.TrimLeft(braceLine, " \t"))]
	bodyIndent := braceIndent + "  "
	var sb strings.Builder
	for i, l := range strings.Split(blockText, "\n") {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(bodyIndent + l)
	}
	return Edit{
		File:      res.Span.File,
		StartLine: end,
		EndLine:   end,
		NewText:   sb.String() + "\n" + braceLine,
	}, true
}

// insertAttrBeforeClose inserts `<name> = <value>` before the closing brace,
// used when the attribute is absent.
func insertAttrBeforeClose(src []byte, res ir.Resource, name, value string) (Edit, bool) {
	return insertBeforeClose(src, res, name+" = "+value)
}

func splitLines(src []byte) []string {
	s := string(src)
	lines := strings.Split(s, "\n")
	if strings.HasSuffix(s, "\n") {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// withDiff renders the patch's unified diff from the source it was
// proposed against.
func withDiff(p Patch, src []byte) Patch {
	files := map[string][]byte{}
	for _, e := range p.Edits {
		files[e.File] = src
	}
	p.Diff = renderDiff(p, files)
	return p
}

// boolFixer flips (or inserts) a boolean attribute. expectFalse means the
// rule fires on a known false/absent value and the fix is `true`; otherwise
// the rule fires on known true and the fix is `false`.
type boolFixer struct {
	ruleID  string
	resType string
	attr    string
	setTrue bool // fix value: true unless the rule fires on true
	desc    string
}

func (b boolFixer) RuleID() string { return b.ruleID }

func (b boolFixer) Propose(f ir.Finding, res ir.Resource, src []byte) []Patch {
	if res.Type != b.resType || f.Evidence.Attribute != b.attr {
		return nil
	}
	want := "true"
	if !b.setTrue {
		want = "false"
	}
	if v, ok := res.Attr(b.attr); ok && v.Known {
		cur, ok := v.AsBool()
		if !ok {
			return nil
		}
		if cur == b.setTrue {
			return nil // already fixed; nothing to do
		}
		edit, ok := attrEdit(src, f, b.attr, want)
		if !ok {
			return nil
		}
		return []Patch{withDiff(Patch{
			RuleID:      b.ruleID,
			Resource:    res.Address(),
			Description: b.desc,
			Edits:       []Edit{edit},
		}, src)}
	}
	// Absent attribute: insert it. (Only valid when the rule fires on
	// absence, i.e. setTrue fixers; a rule firing on `true` never fires
	// on absence.)
	if !b.setTrue {
		return nil
	}
	edit, ok := insertAttrBeforeClose(src, res, b.attr, want)
	if !ok {
		return nil
	}
	return []Patch{withDiff(Patch{
		RuleID:      b.ruleID,
		Resource:    res.Address(),
		Description: b.desc + " (attribute was absent)",
		Edits:       []Edit{edit},
	}, src)}
}

// blockFixer inserts a whole nested block before the resource's closing
// brace, unless the block type already exists.
type blockFixer struct {
	ruleID  string
	resType string
	block   string // block type name, e.g. "server_side_encryption_configuration"
	text    string // block body lines (without outer indent)
	desc    string
}

func (b blockFixer) RuleID() string { return b.ruleID }

func (b blockFixer) Propose(f ir.Finding, res ir.Resource, src []byte) []Patch {
	if res.Type != b.resType {
		return nil
	}
	if _, ok := res.Attr(b.block); ok {
		return nil // block already present (or unknown); don't duplicate
	}
	edit, ok := insertBeforeClose(src, res, b.text)
	if !ok {
		return nil
	}
	return []Patch{withDiff(Patch{
		RuleID:      b.ruleID,
		Resource:    res.Address(),
		Description: b.desc,
		Edits:       []Edit{edit},
	}, src)}
}

type fixer001 struct{ blockFixer }

// newFixer001. Audit: (a) one block insert before the closing brace —
// insertBeforeClose aborts unless the target line is a lone "}" and the
// block is skipped when server_side_encryption_configuration already
// exists; (b) re-parse enforced by ValidatePatch; (c) resType pinned to
// aws_s3_bucket, so no IAM or security-group resource can ever match.
func newFixer001() Fixer {
	return fixer001{blockFixer{
		ruleID:  "AEGIS-AWS-001",
		resType: "aws_s3_bucket",
		block:   "server_side_encryption_configuration",
		text: `server_side_encryption_configuration {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}`,
		desc: "Enable AES256 server-side encryption on the bucket",
	}}
}

type fixer002 struct{}

func (fixer002) RuleID() string { return "AEGIS-AWS-002" }

// fixer002 audit: (a) one attribute line replaced — attrEdit aborts unless
// the evidence span's first line really assigns `acl`, and the replacement
// preserves the original indentation; only known public values from
// publicACLValues are flipped; (b) re-parse enforced by ValidatePatch;
// (c) resType pinned to aws_s3_bucket_acl / aws_s3_bucket and the evidence
// attribute must be exactly "acl" — IAM policies and security-group rules
// cannot match.
func (fixer002) Propose(f ir.Finding, res ir.Resource, src []byte) []Patch {
	// Only the dedicated ACL resource or an inline acl attribute, and only
	// when the evidence shows a known public value.
	if res.Type != "aws_s3_bucket_acl" && res.Type != "aws_s3_bucket" {
		return nil
	}
	if f.Evidence.Attribute != "acl" {
		return nil
	}
	v, ok := res.Attr("acl")
	if !ok || !v.Known {
		return nil
	}
	s, ok := v.AsString()
	if !ok || !publicACLValues[strings.ToLower(strings.TrimSpace(s))] {
		return nil
	}
	edit, ok := attrEdit(src, f, "acl", `"private"`)
	if !ok {
		return nil
	}
	return []Patch{withDiff(Patch{
		RuleID:      "AEGIS-AWS-002",
		Resource:    res.Address(),
		Description: fmt.Sprintf("Change ACL from %q to private", s),
		Edits:       []Edit{edit},
	}, src)}
}

type fixer012 struct{ blockFixer }

// newFixer012. Audit: (a) one block insert before the closing brace,
// skipped when versioning already exists; (b) re-parse enforced by
// ValidatePatch; (c) resType pinned to aws_s3_bucket — no IAM or
// security-group resource can ever match.
func newFixer012() Fixer {
	return fixer012{blockFixer{
		ruleID:  "AEGIS-AWS-012",
		resType: "aws_s3_bucket",
		block:   "versioning",
		text: `versioning {
  enabled = true
}`,
		desc: "Enable versioning on the bucket",
	}}
}

// boolFixer audit (applies to 007/008/009/010/011): (a) one attribute flip
// when the attribute is present and a known wrong value — attrEdit aborts
// on any span mismatch — or one attribute insert before the closing brace
// when absent (only for setTrue fixers); already-correct or non-boolean
// values propose nothing; (b) re-parse enforced by ValidatePatch; (c) each
// constructor pins resType to aws_db_instance, aws_ebs_volume, or
// aws_cloudtrail — no IAM or security-group resource can ever match.
func newFixer007() Fixer {
	return boolFixer{ruleID: "AEGIS-AWS-007", resType: "aws_db_instance",
		attr: "storage_encrypted", setTrue: true,
		desc: "Enable storage encryption on the RDS instance"}
}

func newFixer008() Fixer {
	return boolFixer{ruleID: "AEGIS-AWS-008", resType: "aws_db_instance",
		attr: "deletion_protection", setTrue: true,
		desc: "Enable deletion protection on the RDS instance"}
}

func newFixer009() Fixer {
	return boolFixer{ruleID: "AEGIS-AWS-009", resType: "aws_ebs_volume",
		attr: "encrypted", setTrue: true,
		desc: "Enable encryption on the EBS volume"}
}

func newFixer010() Fixer {
	return boolFixer{ruleID: "AEGIS-AWS-010", resType: "aws_cloudtrail",
		attr: "enable_log_file_validation", setTrue: true,
		desc: "Enable CloudTrail log file validation"}
}

func newFixer011() Fixer {
	return boolFixer{ruleID: "AEGIS-AWS-011", resType: "aws_db_instance",
		attr: "publicly_accessible", setTrue: false,
		desc: "Disable public accessibility on the RDS instance"}
}
