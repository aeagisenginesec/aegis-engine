// Pre-parse hardening for the Terraform adapter.
//
// PreValidate runs cheap structural checks on raw .tf source before the HCL
// parser sees it, so that hopeless input fails fast with a clear,
// actionable error instead of a confusing parser diagnostic (or, worse, a
// silent clean parse). Every error is prefixed with "terraform:" and names
// the file path.
//
// Notes on the checks:
//   - An empty (0-byte) file is NOT an error: empty .tf files are valid and
//     parse to zero resources with zero diagnostics. PreValidate returns nil
//     for them (documented here so the "0 bytes" case is explicit).
//   - The brace/nesting scan is intentionally naive: it skips double-quoted
//     string literals (with backslash escapes), HCL heredocs (<<EOT /
//     <<-EOT), and # / // / /* */ comments, then counts { and }. It is
//     best-effort — the real HCL parser still catches everything else.
//     False positives are possible on exotic-but-valid HCL; the limit
//     constants are generous so that only absurd input trips them.
package terraform

import (
	"bytes"
	"fmt"

	"aegis/internal/discovery"
)

// MaxNestingDepth caps HCL block nesting accepted by PreValidate. Real
// Terraform never nests 50 levels deep; anything beyond that is hostile or
// corrupted input that would risk stack exhaustion downstream.
const MaxNestingDepth = 50

// PreValidate checks raw .tf source for structural problems before parsing.
// It returns nil when the source is safe to hand to the HCL parser —
// including for empty files, which are valid (zero resources).
func PreValidate(path string, src []byte) error {
	if len(src) == 0 {
		// Empty .tf files are valid: nothing to parse, zero resources.
		// Not an error, and deliberately not a warning either.
		return nil
	}
	// UTF-16 check comes before the null-byte check: UTF-16LE text is full
	// of null bytes, and "convert to UTF-8" is the actionable message.
	if bytes.HasPrefix(src, []byte{0xff, 0xfe}) || bytes.HasPrefix(src, []byte{0xfe, 0xff}) {
		return fmt.Errorf("terraform: %s: file appears to be UTF-16 encoded; convert to UTF-8", path)
	}
	if bytes.IndexByte(src, 0x00) >= 0 {
		return fmt.Errorf("terraform: %s: file contains null bytes; not valid UTF-8 HCL", path)
	}
	// Reuse discovery's cap (currently 10 MiB) rather than hardcoding it.
	if int64(len(src)) > discovery.MaxFileBytes {
		return fmt.Errorf("terraform: %s: file exceeds %d MiB limit", path, discovery.MaxFileBytes>>20)
	}
	open, close, maxDepth := scanBraces(src)
	if maxDepth > MaxNestingDepth {
		return fmt.Errorf("terraform: %s: nesting depth exceeds %d levels", path, MaxNestingDepth)
	}
	if open != close {
		return fmt.Errorf("terraform: %s: unbalanced braces: %d open, %d close — file may be truncated", path, open, close)
	}
	return nil
}

// scanBraces counts { and } while skipping string literals, heredocs, and
// comments, and records the maximum brace nesting depth. Best-effort: it
// only needs to catch obvious truncation and absurd nesting.
func scanBraces(src []byte) (open, close, maxDepth int) {
	depth := 0
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '"':
			i = skipString(src, i)
		case c == '#':
			i = skipToNewline(src, i)
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			i = skipToNewline(src, i)
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i = skipBlockComment(src, i)
		case c == '<' && i+1 < len(src) && src[i+1] == '<':
			if ni, ok := skipHeredoc(src, i); ok {
				i = ni
			} else {
				i += 2 // stray "<<", not a heredoc
			}
		case c == '{':
			open++
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
			i++
		case c == '}':
			close++
			if depth > 0 {
				depth--
			}
			i++
		default:
			i++
		}
	}
	return open, close, maxDepth
}

// skipString consumes a double-quoted string starting at src[i] (the quote),
// honoring backslash escapes. An unterminated string consumes to EOF.
func skipString(src []byte, i int) int {
	i++ // opening quote
	for i < len(src) {
		switch src[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1
		default:
			i++
		}
	}
	return len(src)
}

// skipToNewline consumes a line comment through the newline (inclusive).
func skipToNewline(src []byte, i int) int {
	if j := bytes.IndexByte(src[i:], '\n'); j >= 0 {
		return i + j + 1
	}
	return len(src)
}

// skipBlockComment consumes a /* ... */ comment starting at src[i].
// An unterminated comment consumes to EOF.
func skipBlockComment(src []byte, i int) int {
	if j := bytes.Index(src[i+2:], []byte("*/")); j >= 0 {
		return i + 2 + j + 2
	}
	return len(src)
}

// isHeredocIdentChar reports whether c may appear in a heredoc marker.
func isHeredocIdentChar(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

// skipHeredoc consumes an HCL heredoc (<<EOT or <<-EOT) starting at src[i].
// It returns the index just past the terminator line. ok=false means the
// "<<" was not followed by a marker, so it is not a heredoc at all. An
// unterminated heredoc consumes to EOF (best-effort).
func skipHeredoc(src []byte, i int) (next int, ok bool) {
	j := i + 2
	if j < len(src) && src[j] == '-' { // indented heredoc "<<-"
		j++
	}
	start := j
	for j < len(src) && isHeredocIdentChar(src[j]) {
		j++
	}
	if j == start {
		return 0, false
	}
	marker := src[start:j]
	// The body starts on the next line; the heredoc ends at the first line
	// whose trimmed content equals the marker.
	k := j
	if p := bytes.IndexByte(src[k:], '\n'); p >= 0 {
		k += p + 1
	} else {
		return len(src), true
	}
	for k < len(src) {
		e := len(src)
		if p := bytes.IndexByte(src[k:], '\n'); p >= 0 {
			e = k + p
		}
		if bytes.Equal(bytes.TrimSpace(src[k:e]), marker) {
			if p := bytes.IndexByte(src[k:], '\n'); p >= 0 {
				return k + p + 1, true
			}
			return len(src), true
		}
		k = e + 1
	}
	return len(src), true
}
