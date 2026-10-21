// Package discovery safely enumerates IaC files under a target directory.
//
// Safety rules (spec §1 "Safe by default"):
//   - Never follow symlinks (a repo must not redirect the scanner).
//   - Skip VCS and dependency directories (.git, .terraform, node_modules...).
//   - Enforce per-file and total size caps before reading.
//   - Never execute anything found in the target.
package discovery

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// MaxFileBytes caps a single file read (10 MiB).
	MaxFileBytes = 10 << 20
	// MaxTotalBytes caps a whole scan (256 MiB).
	MaxTotalBytes = 256 << 20
	// MaxFiles caps the number of files per scan.
	MaxFiles = 20000
)

// maxFileBytesOverride, when positive, replaces MaxFileBytes for this
// process. Set via SetMaxFileBytes (wired to the CLI --max-file-size flag).
var maxFileBytesOverride int64

// SetMaxFileBytes overrides the per-file size cap (bytes). Non-positive
// values clear the override, restoring the MaxFileBytes default.
func SetMaxFileBytes(n int64) {
	maxFileBytesOverride = n
}

// effectiveMaxFileBytes returns the active per-file cap.
func effectiveMaxFileBytes() int64 {
	if maxFileBytesOverride > 0 {
		return maxFileBytesOverride
	}
	return MaxFileBytes
}

// excludePatterns, when non-empty, skip files whose path matches any glob.
// Set via SetExcludePatterns (wired to the CLI --exclude flag). Patterns
// use KICS-style glob syntax: * matches within a path segment, ** crosses
// segment boundaries, ? matches one character. A pattern is tested against
// the full slash-normalized path and against the base file name, so both
// "vendor/**" and "*.tfvars" work as users expect.
var excludePatterns []string

// SetExcludePatterns replaces the active --exclude glob list.
func SetExcludePatterns(pats []string) {
	excludePatterns = append([]string(nil), pats...)
}

// IsExcluded reports whether path matches any active exclude pattern.
// A pattern without a leading slash matches at any directory depth
// (gitignore-style), so "vendor/**" excludes vendor/ anywhere.
func IsExcluded(path string) bool {
	if len(excludePatterns) == 0 {
		return false
	}
	slash := filepath.ToSlash(path)
	base := filepath.Base(slash)
	for _, pat := range excludePatterns {
		if matchGlob(pat, slash) || matchGlob(pat, base) {
			return true
		}
		if !strings.HasPrefix(pat, "/") && matchGlob("**/"+pat, slash) {
			return true
		}
	}
	return false
}

// matchGlob matches a glob with ** support against a slash-separated path.
func matchGlob(pat, s string) bool {
	re, err := globToRegex(pat)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

var skipDirs = map[string]bool{
	".git": true, ".terraform": true, ".terragrunt-cache": true,
	"node_modules": true, ".hg": true, ".svn": true, "__pycache__": true,
}

var tfExts = map[string]bool{".tf": true, ".tfvars": true}

// manifestExts covers Kubernetes YAML and CloudFormation templates.
// .plan.json is claimed by the planjson adapter (matched by suffix first).
var manifestExts = map[string]bool{".yaml": true, ".yml": true, ".json": true}

// bicepExts covers Bicep files, handled by the bicep adapter.
var bicepExts = map[string]bool{".bicep": true}

// planJSONSuffix matches `terraform show -json` output files.
const planJSONSuffix = ".plan.json"

// isDockerfile reports whether a file name looks like a Dockerfile:
// "Dockerfile", "Dockerfile.<suffix>", or "<name>.dockerfile".
func isDockerfile(name string) bool {
	lower := strings.ToLower(name)
	return lower == "dockerfile" ||
		strings.HasPrefix(lower, "dockerfile.") ||
		strings.HasSuffix(lower, ".dockerfile")
}

// File is a discovered candidate for parsing.
type File struct {
	Path string
	Size int64
}

// Skipped describes a parseable-looking file that discovery dropped
// before parsing (oversize, or the scan-wide total/file-count cap).
// Callers surface these as diagnostics: a dropped file must never vanish
// silently, or its resources' missing findings look like a clean scan.
type Skipped struct {
	Path   string
	Size   int64
	Reason string
}

// Discover walks root and returns parseable IaC files. Symlinks are never
// followed; the walk itself uses Lstat semantics via WalkDir (which does not
// follow symlinks).
func Discover(root string) ([]File, error) {
	files, _, err := DiscoverWithReport(root)
	return files, err
}

// DiscoverWithReport is Discover plus the list of files dropped by the
// size/total caps, so callers can report them instead of silently
// skipping them. The caps themselves are unchanged.
func DiscoverWithReport(root string) ([]File, []Skipped, error) {
	var out []File
	var skipped []Skipped
	var total int64
	capHit := ""
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				// The scan target itself is unreadable: this is a
				// discovery hard failure, not a skippable entry. Failing
				// loudly here prevents reporting a clean "0 findings"
				// scan for a target the scanner could not read at all.
				return fmt.Errorf("cannot read scan target %s: %w", root, err)
			}
			return nil // skip unreadable entries below the root, don't fail the scan
		}
		// Never descend into symlinked directories.
		if d.IsDir() {
			if d.Type()&fs.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip symlinked files outright.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !tfExts[ext] && !manifestExts[ext] && !bicepExts[ext] &&
			!strings.HasSuffix(strings.ToLower(path), planJSONSuffix) &&
			!isDockerfile(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > effectiveMaxFileBytes() {
			// Oversize file: skip, don't OOM — but record it so the
			// caller can emit a diagnostic naming the file and cap.
			skipped = append(skipped, Skipped{
				Path:   path,
				Size:   info.Size(),
				Reason: fmt.Sprintf("file size %d bytes exceeds per-file cap %d bytes (--max-file-size)", info.Size(), effectiveMaxFileBytes()),
			})
			return nil
		}
		if info.Mode().IsRegular() {
			// Probe readability: a file discovery cannot open would
			// otherwise be reported as discovered and only fail later
			// at read time. Skip it here and record why — mid-walk
			// leniency: one unreadable file below the root must not
			// fail the scan, but it must never vanish silently either.
			fh, err := os.Open(path)
			if err != nil {
				skipped = append(skipped, Skipped{
					Path:   path,
					Size:   info.Size(),
					Reason: fmt.Sprintf("file is not readable: %v", err),
				})
				return nil
			}
			fh.Close()
		}
		total += info.Size()
		if total > MaxTotalBytes || len(out) >= MaxFiles {
			if total > MaxTotalBytes {
				capHit = fmt.Sprintf("scan stopped: total size cap %d bytes reached at %s; remaining files not scanned", MaxTotalBytes, path)
			} else {
				capHit = fmt.Sprintf("scan stopped: file-count cap %d reached at %s; remaining files not scanned", MaxFiles, path)
			}
			return filepath.SkipAll
		}
		out = append(out, File{Path: path, Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if capHit != "" {
		skipped = append(skipped, Skipped{Path: root, Reason: capHit})
	}
	return out, skipped, nil
}

// EffectiveMaxFileBytes returns the active per-file size cap (the
// --max-file-size override when set, else MaxFileBytes). Adapters that
// enforce their own size check (e.g. terraform PreValidate) must use this
// instead of the MaxFileBytes constant, or a raised flag raises the
// discovery cap while the parser cap stays at the default and the file
// fails with a confusing message.
func EffectiveMaxFileBytes() int64 { return effectiveMaxFileBytes() }

// globToRegex compiles a glob with ** support to a regexp.
// **/ matches zero or more path segments, ** matches anything,
// * matches within a segment, ? matches one non-separator character.
func globToRegex(pat string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteByte('^')
	i := 0
	for i < len(pat) {
		c := pat[i]
		switch c {
		case '*':
			if i+1 < len(pat) && pat[i+1] == '*' {
				// Consume the "**".
				i += 2
				// "**/" also matches zero segments.
				if i < len(pat) && pat[i] == '/' {
					i++
					b.WriteString("(.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
				i++
			}
		case '?':
			b.WriteString("[^/]")
			i++
		case '[':
			// Character class: copy through to the closing bracket.
			j := i + 1
			if j < len(pat) && pat[j] == '^' {
				j++
			}
			if j < len(pat) && pat[j] == ']' {
				j++
			}
			for j < len(pat) && pat[j] != ']' {
				j++
			}
			if j >= len(pat) {
				return nil, fmt.Errorf("unterminated character class in glob %q", pat)
			}
			b.WriteString(pat[i : j+1])
			i = j + 1
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
			i++
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}

// Read safely reads a discovered file (re-checks size; never follows symlinks).
func Read(f File) ([]byte, error) {
	fi, err := os.Lstat(f.Path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, errSymlink
	}
	if fi.Size() > effectiveMaxFileBytes() {
		return nil, errTooLarge
	}
	return os.ReadFile(f.Path)
}

var (
	errSymlink  = errString("refusing to read symlink")
	errTooLarge = errString("file exceeds size cap")
)

type errString string

func (e errString) Error() string { return string(e) }
