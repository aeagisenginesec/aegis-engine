// Package stage_harness holds throwaway mains used by the Phase 6 audit
// (stagebreak_main.go, rulebreak_main.go, freshrun_main.go).
//
// The mains are tagged `//go:build ignore` so they never participate in
// `go test ./...` / `go build ./...`: they were written against a /tmp
// workload, each declares its own main, and together they break the
// package build. This file exists so the package still has one
// buildable file (naming the package directly reports "no test files"
// instead of "build constraints exclude all Go files").
//
// The mains are preserved as audit evidence. Do not revive them without
// giving each its own directory or a distinct build tag.
package stage_harness
