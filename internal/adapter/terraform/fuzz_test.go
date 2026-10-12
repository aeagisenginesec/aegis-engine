package terraform

import (
	"bytes"
	"strings"
	"testing"
)

// deepNesting builds balanced HCL nested to the given depth.
func deepNesting(levels int) []byte {
	var sb strings.Builder
	for i := 0; i < levels; i++ {
		sb.WriteString(`resource "a" "b" { `)
	}
	for i := 0; i < levels; i++ {
		sb.WriteString(`} `)
	}
	return []byte(sb.String())
}

// FuzzParseModule asserts the parser never panics on arbitrary input and
// never returns a hard error alongside resources (a hard error means the
// module is unusable; partial results must not masquerade as success).
// Run briefly with: go test -fuzz=FuzzParseModule -fuzztime=30s ./internal/adapter/terraform/
func FuzzParseModule(f *testing.F) {
	// Seed corpus: valid input plus every hostile shape PreValidate guards.
	f.Add([]byte(`resource "aws_s3_bucket" "b" { bucket = "x" }`))          // valid minimal
	f.Add([]byte("resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n")) // truncated block
	f.Add([]byte("\xff\xd8\xff\xe0\x00\x10JFIF"))                           // binary garbage
	f.Add([]byte("a\x00b\x00c"))                                            // null bytes
	f.Add([]byte("\xff\xfer\x00e\x00s\x00o\x00u\x00r\x00c\x00e\x00"))       // UTF-16 LE BOM
	f.Add(deepNesting(60))                                                  // 60 levels deep
	f.Add(bytes.Repeat([]byte("x"), 11<<20))                                // 11 MiB of 'x'
	f.Add([]byte(`resource "a" "b" { x = { y = 1 }`))                       // unbalanced braces
	f.Add([]byte{})                                                         // empty file

	f.Fuzz(func(t *testing.T, src []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseModule panicked on %d-byte input: %v", len(src), r)
			}
		}()
		mod, _, err := (Adapter{}).ParseModule("fuzz.tf", src)
		if err != nil {
			if len(mod.Resources) != 0 {
				t.Fatalf("hard error %q but %d resources returned", err, len(mod.Resources))
			}
			return
		}
		// err == nil: resources may be empty (valid empty parse); nothing
		// further to assert — the no-panic invariant is the contract.
	})
}
