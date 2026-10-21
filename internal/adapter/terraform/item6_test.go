package terraform

import (
	"strings"
	"testing"

	"aegis/internal/discovery"
)

// Item 6: the lenient separator-recovery loop capped at 256 iterations,
// but the HCL parser reports only ONE missing separator per pass, so a
// 100-statement jsonencode() policy (~300 missing separators) exhausted
// the cap and fell back to a partial parse that silently dropped the
// policy attribute (0 findings, file still "parsed"). Recovery must
// succeed for this file: no error diagnostic, policy attribute Known.
func TestItem6SloppyPolicyRecovery(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("resource \"aws_iam_policy\" \"big\" {\n policy=jsonencode({ Version=\"2012-10-17\" Statement=[")
	for j := 0; j < 100; j++ {
		if j > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString("{ Effect = \"Allow\" Action = \"s3:*\" Resource = \"arn-1\" }")
	}
	sb.WriteString("] })\n}\n")
	mod, diags, err := Adapter{}.ParseModule("p.tf", []byte(sb.String()))
	if err != nil {
		t.Fatalf("ParseModule returned hard error: %v", err)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("expected recovery to succeed, got error diagnostic: %v", d)
		}
	}
	if len(mod.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(mod.Resources))
	}
	pol, ok := mod.Resources[0].Attributes["policy"]
	if !ok {
		t.Fatal("policy attribute missing after recovery")
	}
	if !pol.Known {
		t.Fatalf("expected policy attribute Known after recovery, got %+v", pol)
	}
}

// Item 6: PreValidate must honor the --max-file-size override (via
// discovery.EffectiveMaxFileBytes), not the 10 MiB constant: a raised
// flag used to raise the discovery cap while this check still failed
// the file with a confusing message.
func TestItem6PreValidateHonorsOverride(t *testing.T) {
	discovery.SetMaxFileBytes(20 << 20)
	defer discovery.SetMaxFileBytes(0)
	src := make([]byte, 11<<20)
	for i := range src {
		src[i] = ' '
	}
	if err := PreValidate("big.tf", src); err != nil {
		t.Fatalf("expected 11 MiB file to pass with 20 MiB override, got: %v", err)
	}
}
