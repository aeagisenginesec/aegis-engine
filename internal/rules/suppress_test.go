package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aegis/internal/ir"
)

func suppressTestResources() []ir.Resource {
	return []ir.Resource{
		{
			Type: "aws_s3_bucket", Name: "a",
			SuppressedRules: []string{"AEGIS-AWS-001"},
		},
		{
			Type: "aws_s3_bucket", Name: "b",
			SuppressedRules: []string{"AEGIS-AWS-001", "AEGIS-AWS-012"},
		},
		{
			Type: "aws_s3_bucket", Name: "c",
			SuppressedRules: []string{"all"},
		},
		{
			Type: "aws_s3_bucket", Name: "d", // no suppressions
		},
	}
}

func suppressTestFindings() []ir.Finding {
	mk := func(rule, res, attr string) ir.Finding {
		return ir.Finding{
			RuleID:   rule,
			Resource: res,
			Evidence: ir.Evidence{Attribute: attr},
		}
	}
	return []ir.Finding{
		mk("AEGIS-AWS-001", "aws_s3_bucket.a", "server_side_encryption_configuration"),
		mk("AEGIS-AWS-012", "aws_s3_bucket.a", "versioning"),
		mk("AEGIS-AWS-001", "aws_s3_bucket.b", "server_side_encryption_configuration"),
		mk("AEGIS-AWS-012", "aws_s3_bucket.b", "versioning"),
		mk("AEGIS-AWS-001", "aws_s3_bucket.c", "server_side_encryption_configuration"),
		mk("AEGIS-AWS-012", "aws_s3_bucket.c", "versioning"),
		mk("AEGIS-AWS-001", "aws_s3_bucket.d", "server_side_encryption_configuration"),
		mk("AEGIS-AWS-001", "aws_s3_bucket.zzz", "server_side_encryption_configuration"), // unknown resource: kept
	}
}

func TestApplyInlineSuppressions(t *testing.T) {
	out := ApplyInlineSuppressions(suppressTestResources(), suppressTestFindings())
	// Kept: 012 on a; (b fully suppressed); (c fully suppressed via all);
	// 001 on d; 001 on zzz (no resource record).
	want := map[string]bool{
		"AEGIS-AWS-012|aws_s3_bucket.a":   true,
		"AEGIS-AWS-001|aws_s3_bucket.d":   true,
		"AEGIS-AWS-001|aws_s3_bucket.zzz": true,
	}
	if len(out) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(out), len(want), out)
	}
	for _, f := range out {
		key := f.RuleID + "|" + f.Resource
		if !want[key] {
			t.Errorf("unexpected surviving finding %s", key)
		}
	}
}

func TestApplyInlineSuppressions_Empty(t *testing.T) {
	if got := ApplyInlineSuppressions(nil, nil); len(got) != 0 {
		t.Fatalf("expected empty, got %d", len(got))
	}
	if got := ApplyInlineSuppressions(suppressTestResources(), nil); len(got) != 0 {
		t.Fatalf("expected empty, got %d", len(got))
	}
	// No suppressions on resources: everything kept.
	fs := suppressTestFindings()
	if got := ApplyInlineSuppressions(nil, fs); len(got) != len(fs) {
		t.Fatalf("expected %d kept, got %d", len(fs), len(got))
	}
}

func TestApplyInlineSuppressions_ScopedToResource(t *testing.T) {
	// Suppression on bucket.a must not affect bucket.d.
	resources := []ir.Resource{{Type: "aws_s3_bucket", Name: "a", SuppressedRules: []string{"AEGIS-AWS-001"}}}
	findings := []ir.Finding{
		{RuleID: "AEGIS-AWS-001", Resource: "aws_s3_bucket.d", Evidence: ir.Evidence{Attribute: "x"}},
	}
	if got := ApplyInlineSuppressions(resources, findings); len(got) != 1 {
		t.Fatalf("cross-resource suppression leaked: got %d", len(got))
	}
}

func TestBaseline_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	findings := suppressTestFindings()
	if err := WriteBaseline(path, findings); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// All fingerprinted findings suppressed.
	if got := ApplyBaseline(b, findings); len(got) != 0 {
		t.Fatalf("expected all suppressed, got %d", len(got))
	}
	// New finding (different attribute) is NOT suppressed.
	extra := append(append([]ir.Finding{}, findings...), ir.Finding{
		RuleID:   "AEGIS-AWS-001",
		Resource: "aws_s3_bucket.a",
		Evidence: ir.Evidence{Attribute: "different_attribute"},
	})
	if got := ApplyBaseline(b, extra); len(got) != 1 {
		t.Fatalf("expected 1 surviving, got %d", len(got))
	}
	// New rule on same resource is NOT suppressed.
	extra2 := append(append([]ir.Finding{}, findings...), ir.Finding{
		RuleID:   "AEGIS-AWS-999",
		Resource: "aws_s3_bucket.a",
		Evidence: ir.Evidence{Attribute: "server_side_encryption_configuration"},
	})
	if got := ApplyBaseline(b, extra2); len(got) != 1 {
		t.Fatalf("expected 1 surviving, got %d", len(got))
	}
}

func TestBaseline_StableBytes(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "b1.json")
	p2 := filepath.Join(dir, "b2.json")
	// Reversed input order must still produce identical bytes.
	f1 := suppressTestFindings()
	f2 := append([]ir.Finding{}, f1...)
	for i, j := 0, len(f2)-1; i < j; i, j = i+1, j-1 {
		f2[i], f2[j] = f2[j], f2[i]
	}
	if err := WriteBaseline(p1, f1); err != nil {
		t.Fatal(err)
	}
	if err := WriteBaseline(p2, f2); err != nil {
		t.Fatal(err)
	}
	b1, _ := os.ReadFile(p1)
	b2, _ := os.ReadFile(p2)
	if string(b1) != string(b2) {
		t.Fatal("baseline bytes not stable across input orders")
	}
	// Fingerprints are deduplicated.
	var decoded struct {
		Fingerprints []Fingerprint `json:"fingerprints"`
	}
	if err := json.Unmarshal(b1, &decoded); err != nil {
		t.Fatal(err)
	}
	seen := map[Fingerprint]bool{}
	for _, fp := range decoded.Fingerprints {
		if seen[fp] {
			t.Fatalf("duplicate fingerprint %v", fp)
		}
		seen[fp] = true
	}
}

func TestBaseline_LoadErrors(t *testing.T) {
	if _, err := LoadBaseline("/nonexistent/path.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{not json"), 0o644)
	if _, err := LoadBaseline(bad); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	// Empty path: nil baseline, no error; ApplyBaseline is a no-op.
	b, err := LoadBaseline("")
	if err != nil || b != nil {
		t.Fatalf("expected nil,nil got %v,%v", b, err)
	}
	fs := suppressTestFindings()
	if got := ApplyBaseline(nil, fs); len(got) != len(fs) {
		t.Fatal("nil baseline should keep everything")
	}
}

func TestFingerprintOf(t *testing.T) {
	f := ir.Finding{
		RuleID:   "AEGIS-AWS-001",
		Resource: "aws_s3_bucket.a",
		Evidence: ir.Evidence{Attribute: "x", Actual: "changes", Span: ir.Span{StartLine: 99}},
	}
	fp := FingerprintOf(f)
	if fp.RuleID != "AEGIS-AWS-001" || fp.Resource != "aws_s3_bucket.a" || fp.Attribute != "x" {
		t.Fatalf("bad fingerprint: %+v", fp)
	}
}

// TestFingerprint_StableAcrossReformat verifies that fingerprints do not
// change when source is reformatted (line numbers shift, blank lines
// added/removed). The fingerprint deliberately excludes spans.
func TestFingerprint_StableAcrossReformat(t *testing.T) {
	mk := func(startLine int) ir.Finding {
		return ir.Finding{
			RuleID:   "AEGIS-AWS-001",
			Resource: "aws_s3_bucket.data",
			Evidence: ir.Evidence{
				Attribute: "server_side_encryption_configuration",
				Span:      ir.Span{File: "main.tf", StartLine: startLine, EndLine: startLine + 2},
			},
		}
	}
	// Same finding, different line numbers (as after gofmt/reformat).
	fp1 := FingerprintOf(mk(10))
	fp2 := FingerprintOf(mk(47))
	if fp1 != fp2 {
		t.Fatalf("fingerprint changed across reformat: %+v vs %+v", fp1, fp2)
	}
}

// TestBaseline_MetadataRoundtrip verifies v2 entries with reason/owner/
// expiry survive a write/load cycle and that expiry is enforced.
func TestBaseline_MetadataRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/baseline.json"
	findings := []ir.Finding{{
		RuleID:   "AEGIS-AWS-001",
		Resource: "aws_s3_bucket.data",
		Evidence: ir.Evidence{Attribute: "server_side_encryption_configuration"},
	}}
	ann := map[Fingerprint]BaselineAnnotation{
		FingerprintOf(findings[0]): {
			Reason:  "legacy bucket, migration tracked in TICKET-123",
			Owner:   "sec-team",
			Expires: "2099-01-01T00:00:00Z",
		},
	}
	if err := WriteBaselineWithMetadata(path, findings, ann); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Matches(findings[0]) {
		t.Fatal("annotated baseline entry does not match")
	}
	if len(b.Entries) != 1 || b.Entries[0].Reason == "" || b.Entries[0].Owner == "" {
		t.Fatalf("metadata lost in roundtrip: %+v", b.Entries)
	}
}

// TestBaseline_ExpiredEntry verifies that expired entries no longer suppress.
func TestBaseline_ExpiredEntry(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/baseline.json"
	findings := []ir.Finding{{
		RuleID:   "AEGIS-AWS-001",
		Resource: "aws_s3_bucket.data",
		Evidence: ir.Evidence{Attribute: "server_side_encryption_configuration"},
	}}
	ann := map[Fingerprint]BaselineAnnotation{
		FingerprintOf(findings[0]): {
			Reason:  "temporary waiver",
			Owner:   "sec-team",
			Expires: "2000-01-01T00:00:00Z", // long past
		},
	}
	if err := WriteBaselineWithMetadata(path, findings, ann); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if b.Matches(findings[0]) {
		t.Fatal("expired baseline entry still suppresses")
	}
}

// TestBaseline_ExpiryVisibility verifies the governance reporting on a
// load: expired entries are listed (so the CLI can warn that the waiver
// lapsed) and unparseable expiry values are listed (they still suppress,
// but must never pass silently).
func TestBaseline_ExpiryVisibility(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/baseline.json"
	mk := func(rule, attr string) ir.Finding {
		return ir.Finding{RuleID: rule, Resource: "aws_s3_bucket.data",
			Evidence: ir.Evidence{Attribute: attr}}
	}
	findings := []ir.Finding{mk("AEGIS-AWS-001", "a1"), mk("AEGIS-AWS-002", "a2"), mk("AEGIS-AWS-004", "a3")}
	ann := map[Fingerprint]BaselineAnnotation{
		FingerprintOf(findings[0]): {Reason: "old waiver", Owner: "sec-team", Expires: "2000-01-01T00:00:00Z"},
		FingerprintOf(findings[1]): {Reason: "typo waiver", Owner: "sec-team", Expires: "next-tuesday"},
		FingerprintOf(findings[2]): {Reason: "live waiver", Owner: "sec-team", Expires: "2099-01-01T00:00:00Z"},
	}
	if err := WriteBaselineWithMetadata(path, findings, ann); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	expired := b.ExpiredEntries()
	if len(expired) != 1 || expired[0].RuleID != "AEGIS-AWS-001" {
		t.Fatalf("expected the lapsed waiver reported, got %+v", expired)
	}
	invalid := b.InvalidExpiryEntries()
	if len(invalid) != 1 || invalid[0].RuleID != "AEGIS-AWS-002" {
		t.Fatalf("expected the unparseable-expiry waiver reported, got %+v", invalid)
	}
	if !b.Matches(findings[1]) {
		t.Error("unparseable-expiry entry should still suppress (fail-open, but reported)")
	}
	if !b.Matches(findings[2]) {
		t.Error("live waiver should suppress")
	}
}

// TestBaseline_V1BackCompat verifies old flat-format baselines still load.
func TestBaseline_V1BackCompat(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/v1.json"
	raw := `{"version":1,"fingerprints":[{"rule_id":"AEGIS-AWS-001","resource":"aws_s3_bucket.data","attribute":"server_side_encryption_configuration"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	f := ir.Finding{
		RuleID:   "AEGIS-AWS-001",
		Resource: "aws_s3_bucket.data",
		Evidence: ir.Evidence{Attribute: "server_side_encryption_configuration"},
	}
	if !b.Matches(f) {
		t.Fatal("v1 baseline no longer matches")
	}
}
