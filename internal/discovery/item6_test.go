package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Item 6: an over-cap file used to vanish from discovery with no record
// at all (0 findings that looked clean). DiscoverWithReport must list it
// as skipped with the cap in the reason.
func TestItem6OverCapReported(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "ok.tf")
	if err := os.WriteFile(small, []byte("resource \"aws_s3_bucket\" \"b\" { bucket = \"x\" }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.tf")
	// Just over the 10 MiB default cap.
	data := make([]byte, MaxFileBytes+1)
	for i := range data {
		data[i] = '#'
	}
	if err := os.WriteFile(big, data, 0o644); err != nil {
		t.Fatal(err)
	}
	files, skipped, err := DiscoverWithReport(dir)
	if err != nil {
		t.Fatalf("DiscoverWithReport: %v", err)
	}
	if len(files) != 1 || files[0].Path != small {
		t.Fatalf("expected only the small file discovered, got %v", files)
	}
	if len(skipped) != 1 || skipped[0].Path != big {
		t.Fatalf("expected the over-cap file in skipped, got %v", skipped)
	}
	if !strings.Contains(skipped[0].Reason, "exceeds per-file cap") {
		t.Fatalf("expected cap reason, got %q", skipped[0].Reason)
	}
}
