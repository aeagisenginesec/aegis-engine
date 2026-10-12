// Package discovery safely enumerates IaC files under a target directory.
//
// Safety rules (spec §1 "Safe by default"):
//   - Never follow symlinks (a repo must not redirect the scanner).
//   - Skip VCS and dependency directories (.git, .terraform, node_modules...).
//   - Enforce per-file and total size caps before reading.
//   - Never execute anything found in the target.
package discovery

import (
	"io/fs"
	"os"
	"path/filepath"
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

var skipDirs = map[string]bool{
	".git": true, ".terraform": true, ".terragrunt-cache": true,
	"node_modules": true, ".hg": true, ".svn": true, "__pycache__": true,
}

var tfExts = map[string]bool{".tf": true, ".tfvars": true}

// manifestExts covers Kubernetes YAML and CloudFormation templates.
// .plan.json is claimed by the planjson adapter (matched by suffix first).
var manifestExts = map[string]bool{".yaml": true, ".yml": true, ".json": true}

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

// Discover walks root and returns parseable IaC files. Symlinks are never
// followed; the walk itself uses Lstat semantics via WalkDir (which does not
// follow symlinks).
func Discover(root string) ([]File, error) {
	var out []File
	var total int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, don't fail the scan
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
		if !tfExts[ext] && !manifestExts[ext] &&
			!strings.HasSuffix(strings.ToLower(path), planJSONSuffix) &&
			!isDockerfile(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > effectiveMaxFileBytes() {
			return nil // oversize file: skip, don't OOM
		}
		total += info.Size()
		if total > MaxTotalBytes || len(out) >= MaxFiles {
			return filepath.SkipAll
		}
		out = append(out, File{Path: path, Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
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
