package advisories

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "advisories.json")
	content := `[
	  {"id": "CVE-2024-1234", "package": "hashicorp/aws", "affected": ">= 4.0.0, < 5.2.0", "severity": "high"},
	  {"id": "GHSA-abcd-efgh", "package": "hashicorp/azurerm", "affected": "< 3.0.0", "severity": "critical"}
	]`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	advs, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(advs) != 2 {
		t.Fatalf("got %d advisories, want 2", len(advs))
	}
	if advs[0].ID != "CVE-2024-1234" || advs[0].Package != "hashicorp/aws" ||
		advs[0].Affected != ">= 4.0.0, < 5.2.0" || advs[0].Severity != "high" {
		t.Errorf("first advisory wrong: %+v", advs[0])
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("Load of missing file should error")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Error("Load of invalid JSON should error")
	}
}

func TestAffected(t *testing.T) {
	cases := []struct {
		version  string
		affected string
		want     bool
	}{
		// basic ranges
		{"5.1.0", ">= 4.0.0, < 5.2.0", true},
		{"5.2.0", ">= 4.0.0, < 5.2.0", false},
		{"4.0.0", ">= 4.0.0, < 5.2.0", true},
		{"3.9.9", ">= 4.0.0, < 5.2.0", false},
		// operators
		{"4.0.0", ">= 4.0.0", true},
		{"1.0.0", "<= 1.0.0", true},
		{"1.0.1", "<= 1.0.0", false},
		{"2.0.0", "> 1.9.9", true},
		{"1.9.9", "> 1.9.9", false},
		{"1.9.9", "< 2.0.0", true},
		{"2.0.0", "< 2.0.0", false},
		{"1.2.3", "= 1.2.3", true},
		{"1.2.4", "= 1.2.3", false},
		{"1.2.3", "== 1.2.3", true},
		{"1.2.3", "1.2.3", true}, // bare version means equality
		// pessimistic
		{"4.5.0", "~> 4.2", true},
		{"5.0.0", "~> 4.2", false},
		{"4.1.9", "~> 4.2", false},
		{"4.2.5", "~> 4.2.1", true},
		{"4.3.0", "~> 4.2.1", false},
		{"4.2.0", "~> 4.2.1", false},
		{"4.0", "~> 4", true},
		{"5.0", "~> 4", false},
		// missing parts are 0
		{"1.2", "1.2.0", true},
		{"1.2.0", "= 1.2", true},
		// garbage never matches
		{"abc", ">= 1.0.0", false},
		{"", ">= 1.0.0", false},
		{"1.2.3-beta", ">= 1.0.0", false},
		{"1.0.0", "garbage", false},
		{"1.0.0", "", false},
		{"1.0.0", ">= 1.0.0,", false}, // trailing comma -> empty clause
		{"1.0.0", ">= a.b", false},
		{"v1.2.3", ">= 1.0.0", false}, // v-prefix is not a plain version
	}
	for _, c := range cases {
		a := Advisory{ID: "TEST", Affected: c.affected}
		if got := Affected(a, c.version); got != c.want {
			t.Errorf("Affected(%q, %q) = %v, want %v", c.affected, c.version, got, c.want)
		}
	}
}

func TestIsConcreteVersion(t *testing.T) {
	for _, s := range []string{"5.1.0", "4.2", "1", " 2.0.1 "} {
		if !IsConcreteVersion(s) {
			t.Errorf("IsConcreteVersion(%q) = false, want true", s)
		}
	}
	for _, s := range []string{">= 5.0", "~> 4.2", "*", ">= 4.0, < 5.0", "", "abc", "1.2-beta"} {
		if IsConcreteVersion(s) {
			t.Errorf("IsConcreteVersion(%q) = true, want false", s)
		}
	}
}
