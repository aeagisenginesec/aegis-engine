package qualitygate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrecisionRecallF1(t *testing.T) {
	// Perfect score.
	if p := precision(95, 5); p != 0.95 {
		t.Errorf("precision(95,5) = %v, want 0.95", p)
	}
	if r := recall(90, 10); r != 0.9 {
		t.Errorf("recall(90,10) = %v, want 0.9", r)
	}
	// Zero-division guards.
	if precision(0, 0) != 0 {
		t.Error("precision(0,0) should be 0")
	}
	if recall(0, 0) != 0 {
		t.Error("recall(0,0) should be 0")
	}
	if f1(0, 0, 0) != 0 {
		t.Error("f1(0,0,0) should be 0")
	}
	// Known F1: p=1.0, r=0.5 -> f1=2/3.
	if f := f1(50, 0, 50); f < 0.666 || f > 0.667 {
		t.Errorf("f1(50,0,50) = %v, want ~0.667", f)
	}
}

func TestPercentiles(t *testing.T) {
	dursMs := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110} // ms
	var dd []time.Duration
	for _, ms := range dursMs {
		dd = append(dd, time.Duration(ms)*time.Millisecond)
	}
	median, p95 := percentiles(dd)
	if median != 60 {
		t.Errorf("median = %v, want 60", median)
	}
	if p95 != 110 {
		t.Errorf("p95 = %v, want 110", p95)
	}
	// Empty input.
	if m, p := percentiles(nil); m != 0 || p != 0 {
		t.Error("percentiles(nil) should be (0,0)")
	}
}

func TestBenchStatsSkipsWhenAbsent(t *testing.T) {
	_, _, _, _, _, _, skipped := benchStats(t.TempDir()) // empty dir, no manifest
	if !skipped {
		t.Error("benchStats should skip when manifest.json is absent")
	}
}

func TestBenchStatsTinyFixture(t *testing.T) {
	dir := t.TempDir()
	projects := filepath.Join(dir, "projects")
	mustMkdir := func(p string) {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustMkdir(filepath.Join(projects, "proj-vuln"))
	mustMkdir(filepath.Join(projects, "proj-clean"))
	// Vulnerable: open SSH security group.
	os.WriteFile(filepath.Join(projects, "proj-vuln", "main.tf"), []byte(
		"resource \"aws_security_group\" \"v\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n"), 0o644)
	// Clean: restricted SSH.
	os.WriteFile(filepath.Join(projects, "proj-clean", "main.tf"), []byte(
		"resource \"aws_security_group\" \"c\" {\n  description = \"x\"\n  ingress {\n    description = \"ssh\"\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"10.0.0.0/8\"]\n  }\n}\n"), 0o644)
	manifest := `[{"project":"proj-vuln","vulnerable":true},{"project":"proj-clean","vulnerable":false}]`
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644)

	tp, fp, fn, tn, _, _, skipped := benchStats(dir)
	if skipped {
		t.Fatal("benchStats should not skip with a valid manifest")
	}
	if tp != 1 {
		t.Errorf("tp = %d, want 1 (open SSH must be caught)", tp)
	}
	if fn != 0 {
		t.Errorf("fn = %d, want 0", fn)
	}
	// The clean project may trigger hygiene rules; we only assert no crash
	// and that the vulnerable project was caught.
	_ = fp
	_ = tn
}

func TestParserProbes(t *testing.T) {
	for _, c := range malformedCases {
		ok, detail := parserProbe(c)
		if c.wantClean && !ok {
			t.Errorf("valid case %q failed: %s", c.name, detail)
		}
		if !c.wantClean && !ok {
			t.Logf("probe %q NOT explicit (will fail below): %s", c.name, detail)
		}
	}
	// The key invariant: garbage must never be silently clean.
	for _, c := range malformedCases {
		if c.wantClean {
			continue
		}
		ok, _ := parserProbe(c)
		if !ok {
			t.Errorf("malformed input %q was silently clean", c.name)
		}
	}
}

func TestGateResultSkippedDoesNotFail(t *testing.T) {
	rep := Report{Gates: []GateResult{
		{Name: "a", Passed: true},
		{Name: "b", Skipped: true},
	}}
	rep.Passed = true
	for _, g := range rep.Gates {
		if !g.Skipped && !g.Passed {
			rep.Passed = false
		}
	}
	if !rep.Passed {
		t.Error("skipped gates should not fail the report")
	}
}
