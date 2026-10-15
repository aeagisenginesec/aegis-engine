package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

// Audit 2026-10-14: scanning an unreadable ROOT directory used to print
// "resources: 0, findings: 0" with exit 0 and no diagnostic — a silent
// fail-open that contradicts the package contract ("a discovery hard
// failure is returned as an error"). The walk callback swallowed the root
// read error like any mid-walk entry. Now a root-level walk error is a
// hard discovery error (callers map it to exit 2).
func TestAuditUnreadableRootIsHardError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unreadable-dir probe needs a non-root user; root bypasses permission checks")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(dir, 0o755)

	_, _, err := DiscoverWithReport(dir)
	if err == nil {
		t.Fatal("expected a hard error discovering an unreadable root, got nil")
	}
}

// A single unreadable file below a readable root must still be skipped,
// not fail the scan (mid-walk leniency is by design).
func TestAuditUnreadableFileBelowRootSkipped(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unreadable-file probe needs a non-root user; root bypasses permission checks")
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "ok.tf")
	if err := os.WriteFile(good, []byte("resource \"x\" \"y\" {}\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	bad := filepath.Join(dir, "bad.tf")
	if err := os.WriteFile(bad, []byte("resource \"x\" \"y\" {}\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(bad, 0o644)

	files, _, err := DiscoverWithReport(dir)
	if err != nil {
		t.Fatalf("mid-walk unreadable file must not fail discovery, got: %v", err)
	}
	for _, f := range files {
		if f.Path == bad {
			t.Fatal("unreadable file should be skipped by discovery")
		}
	}
}
