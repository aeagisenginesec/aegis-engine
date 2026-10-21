package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Item 6: end-to-end over-cap reporting. An 11 MiB file must appear in
// scan completeness as skipped with a diagnostic naming the cap (it used
// to vanish silently), while a valid sibling file is still scanned.
func TestItem6OverCapEndToEnd(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.tf"),
		[]byte("resource \"aws_s3_bucket\" \"b\" { bucket = \"x\" acl = \"public-read\" }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.tf")
	data := make([]byte, 11<<20)
	for i := range data {
		data[i] = '#'
	}
	if err := os.WriteFile(big, data, 0o644); err != nil {
		t.Fatal(err)
	}
	res, _, _, err := scanFull(dir, defaultAdapters(), nil)
	if err != nil {
		t.Fatalf("scanFull: %v", err)
	}
	foundDiag := false
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Message, "big.tf") && strings.Contains(d.Message, "exceeds per-file cap") {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected over-cap diagnostic for big.tf, got %v", res.Diagnostics)
	}
	foundSkip := false
	for _, f := range res.Completeness.Files {
		if f.Path == big && f.Status == "skipped" {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Fatalf("expected big.tf in completeness as skipped, got %+v", res.Completeness.Files)
	}
	if res.Completeness.FilesDiscovered != 2 {
		t.Fatalf("expected 2 discovered files, got %d", res.Completeness.FilesDiscovered)
	}
}
