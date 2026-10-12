// Package remediation proposes source patches for scanner findings and
// validates them by re-scanning an isolated copy.
//
// Milestone 4 scope: deterministic, unambiguous fixes only (boolean flips,
// safe block insertions). Anything needing human judgment — CIDR ranges,
// IAM policy rewrites, trust redesign, attack-path correlation — gets NO
// auto-fix; ProposeAll simply yields nothing for those rules.
//
// Safety: patches never touch the original tree. ValidatePatch copies the
// target to a temp dir, applies edits there, and re-scans. ApplyEdits
// rejects overlapping or out-of-range edits instead of corrupting content.
package remediation

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aegis/internal/ir"
)

// copySizeLimit mirrors the discovery philosophy: a single validation run
// never copies more than 256 MiB.
const copySizeLimit = 256 << 20

// Edit replaces lines [StartLine, EndLine] (1-based, inclusive) of File
// with NewText. NewText may span multiple lines.
type Edit struct {
	File      string // path as it appears in spans; used as given
	StartLine int    // 1-based, inclusive
	EndLine   int    // 1-based, inclusive
	NewText   string // replacement text, may be multi-line
}

// Patch is one proposed fix for one finding.
type Patch struct {
	RuleID      string
	Resource    string // "type.name"
	Description string
	Edits       []Edit
	Diff        string // human-readable unified diff for display
}

// Fixer proposes patches for findings of one rule. It must be deterministic
// and never panic; when the fix is not unambiguous it returns no patches.
type Fixer interface {
	RuleID() string
	Propose(f ir.Finding, res ir.Resource, src []byte) []Patch
}

// DefaultFixers returns every fixer, sorted by rule ID.
func DefaultFixers() []Fixer {
	fixers := []Fixer{
		newFixer001(),
		fixer002{},
		newFixer007(),
		newFixer008(),
		newFixer009(),
		newFixer010(),
		newFixer011(),
		newFixer012(),
	}
	sort.Slice(fixers, func(i, j int) bool { return fixers[i].RuleID() < fixers[j].RuleID() })
	return fixers
}

// ApplyEdits applies line-span replacements to content. Edits are applied
// from the bottom up so earlier spans don't shift. Overlapping or
// out-of-range edits are rejected with an error — content is never
// silently corrupted.
func ApplyEdits(content string, edits []Edit) (string, error) {
	trailingNL := strings.HasSuffix(content, "\n")
	lines := strings.Split(content, "\n")
	if trailingNL {
		lines = lines[:len(lines)-1]
	}
	ordered := append([]Edit(nil), edits...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].StartLine != ordered[j].StartLine {
			return ordered[i].StartLine > ordered[j].StartLine // bottom-up
		}
		return ordered[i].EndLine > ordered[j].EndLine
	})
	// applied holds original-coordinate intervals of edits already done
	// (all below the current one, so coordinates are still valid).
	var applied [][2]int
	for _, e := range ordered {
		if e.StartLine < 1 || e.EndLine < e.StartLine || e.EndLine > len(lines) {
			return "", fmt.Errorf("remediation: edit out of range [%d,%d] for %d-line file %q",
				e.StartLine, e.EndLine, len(lines), e.File)
		}
		for _, a := range applied {
			if e.StartLine <= a[1] && e.EndLine >= a[0] {
				return "", fmt.Errorf("remediation: overlapping edits in %q ([%d,%d] overlaps [%d,%d])",
					e.File, e.StartLine, e.EndLine, a[0], a[1])
			}
		}
		applied = append(applied, [2]int{e.StartLine, e.EndLine})
		newLines := strings.Split(e.NewText, "\n")
		// Rebuild: lines before, new text, lines after.
		out := make([]string, 0, len(lines)-(e.EndLine-e.StartLine+1)+len(newLines))
		out = append(out, lines[:e.StartLine-1]...)
		out = append(out, newLines...)
		out = append(out, lines[e.EndLine:]...)
		lines = out
	}
	result := strings.Join(lines, "\n")
	if trailingNL {
		result += "\n"
	}
	return result, nil
}

// renderDiff renders a minimal unified diff for a patch using the cached
// file contents.
func renderDiff(p Patch, files map[string][]byte) string {
	var sb strings.Builder
	edits := append([]Edit(nil), p.Edits...)
	sort.Slice(edits, func(i, j int) bool {
		if edits[i].File != edits[j].File {
			return edits[i].File < edits[j].File
		}
		return edits[i].StartLine < edits[j].StartLine
	})
	for _, e := range edits {
		src, ok := files[e.File]
		if !ok {
			continue
		}
		lines := strings.Split(string(src), "\n")
		if strings.HasSuffix(string(src), "\n") {
			lines = lines[:len(lines)-1]
		}
		sb.WriteString("--- a/" + e.File + "\n")
		sb.WriteString("+++ b/" + e.File + "\n")
		oldCount := e.EndLine - e.StartLine + 1
		newLines := strings.Split(e.NewText, "\n")
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", e.StartLine, oldCount, e.StartLine, len(newLines))
		lo, hi := e.StartLine-1, e.EndLine
		if lo < 0 {
			lo = 0
		}
		if hi > len(lines) {
			hi = len(lines)
		}
		for _, l := range lines[lo:hi] {
			sb.WriteString("-" + l + "\n")
		}
		for _, l := range newLines {
			sb.WriteString("+" + l + "\n")
		}
	}
	return sb.String()
}

// ProposeAll matches findings to resources and fixers, reads each file once,
// and returns patches sorted by (rule ID, resource). Rules without a fixer
// (003/004/005/006, 101-104: human judgment required) yield nothing.
//
// Safety gate: findings whose resource type is on the dangerous-resource
// blocklist (see safety.go) are skipped unless AllowBlocked is set. This is
// a type-level backstop on top of the fixers themselves, which never address
// blocked types; it also guards any future fixer that would.
func ProposeAll(findings []ir.Finding, resources []ir.Resource, readFile func(path string) ([]byte, error)) []Patch {
	return proposeAllWithFixers(findings, resources, readFile, DefaultFixers())
}

// proposeAllWithFixers is ProposeAll over an explicit fixer set, used by
// tests to inject probe fixers for blocked resource types.
func proposeAllWithFixers(findings []ir.Finding, resources []ir.Resource, readFile func(path string) ([]byte, error), fixers []Fixer) []Patch {
	byAddr := make(map[string]ir.Resource, len(resources))
	for _, r := range resources {
		if _, ok := byAddr[r.Address()]; !ok {
			byAddr[r.Address()] = r
		}
	}
	fixerByID := make(map[string]Fixer)
	for _, fx := range fixers {
		fixerByID[fx.RuleID()] = fx
	}
	sorted := append([]ir.Finding(nil), findings...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].RuleID != sorted[j].RuleID {
			return sorted[i].RuleID < sorted[j].RuleID
		}
		return sorted[i].Resource < sorted[j].Resource
	})
	files := map[string][]byte{}
	var patches []Patch
	for _, f := range sorted {
		fx, ok := fixerByID[f.RuleID]
		if !ok {
			continue // no auto-fix for this rule
		}
		res, ok := byAddr[f.Resource]
		if !ok {
			continue // resource not in this scan; nothing to patch
		}
		if !AllowBlocked && IsBlocked(res.Type) {
			continue // dangerous resource type (IAM/networking); needs --force
		}
		path := f.Evidence.Span.File
		src, ok := files[path]
		if !ok {
			b, err := readFile(path)
			if err != nil {
				continue // unreadable file: skip, never fail the batch
			}
			src = b
			files[path] = src
		}
		for _, p := range fx.Propose(f, res, src) {
			if p.Diff == "" {
				p.Diff = renderDiff(p, files)
			}
			patches = append(patches, p)
		}
	}
	sort.Slice(patches, func(i, j int) bool {
		if patches[i].RuleID != patches[j].RuleID {
			return patches[i].RuleID < patches[j].RuleID
		}
		return patches[i].Resource < patches[j].Resource
	})
	return patches
}

// Validation is the result of re-scanning a patched copy.
type Validation struct {
	Patch       Patch
	Fixed       bool         // the target finding is gone after the patch
	NewFindings []ir.Finding // findings introduced by the patch (must be empty to apply)
	// ResourceMissing is set when the patched target resource no longer
	// parses after the patch. Absence of the finding then proves nothing —
	// the patch corrupted the file, so Fixed is forced false.
	ResourceMissing bool
}

// countErrors counts error-level diagnostics.
func countErrors(diags []ir.Diagnostic) int {
	n := 0
	for _, d := range diags {
		if d.Level == "error" {
			n++
		}
	}
	return n
}

// findingKey identifies a finding for before/after comparison.
func findingKey(f ir.Finding) string {
	return f.RuleID + "\x00" + f.Resource + "\x00" + f.Evidence.Attribute
}

// ValidatePatch scans the original dir, copies it to a temp dir, applies
// the patch there, and re-scans. Fixed is true when no finding with the
// patch's RuleID+Resource remains; NewFindings lists findings present after
// but not before. The original tree is never modified. Two extra safety
// gates: the patched target resource must still parse (a corrupted file
// that drops the resource must never read as "fixed"), and error-level
// diagnostics must not increase.
func ValidatePatch(targetDir string, p Patch, scan func(dir string) (ir.ScanResult, []ir.Resource, error)) (Validation, error) {
	v := Validation{Patch: p}
	before, _, err := scan(targetDir)
	if err != nil {
		return v, fmt.Errorf("remediation: before-scan failed: %w", err)
	}
	tmp, err := os.MkdirTemp("", "aegis-remediation-*")
	if err != nil {
		return v, fmt.Errorf("remediation: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	if err := copyTree(targetDir, tmp); err != nil {
		return v, err
	}
	// Group edits per file and apply to the temp copy.
	byFile := map[string][]Edit{}
	for _, e := range p.Edits {
		rel, err := filepath.Rel(targetDir, e.File)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			return v, fmt.Errorf("remediation: patch file %q is outside the scan target", e.File)
		}
		byFile[rel] = append(byFile[rel], e)
	}
	for rel, edits := range byFile {
		full := filepath.Join(tmp, rel)
		content, err := os.ReadFile(full)
		if err != nil {
			return v, fmt.Errorf("remediation: read temp file %q: %w", rel, err)
		}
		patched, err := ApplyEdits(string(content), edits)
		if err != nil {
			return v, fmt.Errorf("remediation: apply edits to %q: %w", rel, err)
		}
		if err := os.WriteFile(full, []byte(patched), 0o644); err != nil {
			return v, fmt.Errorf("remediation: write temp file %q: %w", rel, err)
		}
	}
	after, afterRes, err := scan(tmp)
	if err != nil {
		return v, fmt.Errorf("remediation: after-scan failed: %w", err)
	}
	// Safety gate 1: the target resource must still parse after the patch.
	// A patch that corrupts the file drops the resource, which also drops
	// the finding — absence then proves nothing.
	v.ResourceMissing = true
	for _, r := range afterRes {
		if r.Address() == p.Resource {
			v.ResourceMissing = false
			break
		}
	}
	if v.ResourceMissing {
		v.Fixed = false
		return v, nil
	}
	// Safety gate 2: error diagnostics must not increase.
	if countErrors(after.Diagnostics) > countErrors(before.Diagnostics) {
		v.Fixed = false
		return v, nil
	}
	fixed := true
	for _, f := range after.Findings {
		if f.RuleID == p.RuleID && f.Resource == p.Resource {
			fixed = false
			break
		}
	}
	v.Fixed = fixed
	beforeKeys := make(map[string]bool, len(before.Findings))
	for _, f := range before.Findings {
		beforeKeys[findingKey(f)] = true
	}
	for _, f := range after.Findings {
		if !beforeKeys[findingKey(f)] {
			v.NewFindings = append(v.NewFindings, f)
		}
	}
	return v, nil
}

// copyTree copies regular files from src to dst, skipping .git, .terraform,
// and symlinks, bounded at copySizeLimit total bytes.
func copyTree(src, dst string) error {
	var total int64
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".terraform" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never follow symlinks
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		if total > copySizeLimit {
			return fmt.Errorf("remediation: copy exceeds %d MiB limit", copySizeLimit>>20)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(filepath.Join(dst, rel), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}
