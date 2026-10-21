// Package version carries the Aegis release version stamped into the binary
// and every report envelope. Values are set at build time via -ldflags:
//
//	go build -ldflags "-X aegis/internal/version.BuildDate=2026-10-11 -X aegis/internal/version.Commit=abc123"
//
// Defaults are used when ldflags are not provided.
package version

// Version is the current Aegis release.
const Version = "2.1.0"

// BuildDate is stamped at build time (YYYY-MM-DD). Defaults to unknown.
var BuildDate = "unknown"

// Commit is the git commit hash stamped at build time. Defaults to unknown.
var Commit = "unknown"

// String returns a human-readable version line.
func String() string {
	return "aegis " + Version + " (build " + BuildDate + ", commit " + Commit + ")"
}
