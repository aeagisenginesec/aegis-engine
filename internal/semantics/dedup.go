package semantics

import (
	"path/filepath"
	"strings"

	"aegis/internal/ir"
)

// twinKey identifies one source block: its file (normalized to an absolute
// path, because root parsing uses discovery paths while module expansion
// uses absolute paths), its full span, and its resource type. Two resources
// with the same key are the same source block parsed twice — never two
// distinct resources, since one file cannot contain two blocks at the
// same span.
type twinKey struct {
	file      string
	startLine int
	startCol  int
	endLine   int
	endCol    int
	typ       string
}

func twinKeyOf(r ir.Resource) twinKey {
	file := canonicalFile(r.Span.File)
	return twinKey{
		file:      file,
		startLine: r.Span.StartLine,
		startCol:  r.Span.StartCol,
		endLine:   r.Span.EndLine,
		endCol:    r.Span.EndCol,
		typ:       r.Type,
	}
}

// canonicalFile returns the absolute, symlink-resolved form of a source
// file path, so resources recorded with different path spellings still
// compare equal: relative vs absolute (root parsing uses discovery paths
// while module expansion uses absolute paths), and paths that pass
// through a symlinked directory (macOS temp dirs live under /var, which
// is a symlink to /private/var, so os.Getwd() resolves it while the
// stored path does not).
//
// The file itself may not exist (synthetic spans in tests), so symlinks
// are resolved on the longest existing ancestor and the remainder is
// re-appended. If nothing resolves, the plain absolute path is returned.
func canonicalFile(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	dir := abs
	var rest []string
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return abs // reached the root without resolving anything
		}
		rest = append([]string{filepath.Base(dir)}, rest...)
		dir = parent
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(append([]string{resolved}, rest...)...)
		}
	}
}

// isModuleAddressed reports whether the resource came from module
// expansion: expanded names carry a `module.<name>.` prefix (nested
// modules: `module.l1.module.l2.`). Bare Terraform labels cannot contain
// dots, so a bare resource name never starts with `module.`.
func isModuleAddressed(r ir.Resource) bool {
	return strings.HasPrefix(r.Name, "module.")
}

// RemoveBareModuleTwins drops bare-address resources that duplicate a
// module-expanded resource.
//
// Root cause: runScan parses every discovered .tf file as a root, so a
// file inside a module directory yields bare-address resources
// (aws_s3_bucket.uploads). ExpandModules then re-parses the same files
// and yields the same resources with module-prefixed addresses
// (aws_s3_bucket.module.data.uploads). Without dedup, every rule fires
// twice on the same source block.
//
// The expanded copy is authoritative: it carries the correct Terraform
// address, module-input-resolved attributes, and rewritten intra-module
// references. The bare copy is the spurious one and is dropped.
//
// Safety properties:
//   - A bare resource is dropped only when an expanded twin shares its
//     exact (file, span, type). Bare resources with no expanded twin
//     survive: expansion failures (remote source, depth limit, cycle)
//     and scans of a module directory itself (no caller) keep reporting.
//   - Distinct resources that share a name in different modules live in
//     different files, so their keys differ and both survive.
//   - Multiple instances of the same module (two callers, same source)
//     each produce an expanded copy; both survive, and only the single
//     bare copy is dropped.
//   - Non-Terraform resources have no expanded twins and are untouched.
func RemoveBareModuleTwins(all, expanded []ir.Resource) []ir.Resource {
	if len(expanded) == 0 {
		return all
	}
	twins := make(map[twinKey]bool, len(expanded))
	for _, r := range expanded {
		twins[twinKeyOf(r)] = true
	}
	out := make([]ir.Resource, 0, len(all))
	for _, r := range all {
		if !isModuleAddressed(r) && twins[twinKeyOf(r)] {
			continue // bare twin of an expanded resource: drop
		}
		out = append(out, r)
	}
	return out
}
