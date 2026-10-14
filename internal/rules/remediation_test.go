package rules

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

func TestRemediationFor_DetailedEntry(t *testing.T) {
	fix, refs := RemediationFor("AEGIS-AWS-001")
	if !strings.Contains(fix, "server_side_encryption_configuration") {
		t.Errorf("AEGIS-AWS-001 fix should mention server_side_encryption_configuration, got: %q", fix[:80])
	}
	if len(refs) == 0 {
		t.Error("AEGIS-AWS-001 should have reference URLs")
	}
}

func TestRemediationFor_CriticalEntries(t *testing.T) {
	critical := []string{
		"AEGIS-AWS-003", "AEGIS-AWS-006", "AEGIS-AWS-101", "AEGIS-AWS-104",
		"AEGIS-AWS-202", "AEGIS-AWS-501", "AEGIS-AWS-502", "AEGIS-AWS-534",
		"AEGIS-AWS-629", "AEGIS-GCP-001", "AEGIS-K8S-001",
	}
	for _, id := range critical {
		fix, refs := RemediationFor(id)
		if fix == "" {
			t.Errorf("%s: empty remediation", id)
		}
		if len(refs) == 0 {
			t.Errorf("%s: no references", id)
		}
	}
}

func TestRemediationFor_FallbackNeverEmpty(t *testing.T) {
	// Every rule in the registry must get non-empty guidance.
	for _, r := range DefaultRegistry().All() {
		fix, refs := RemediationFor(r.ID())
		if fix == "" {
			t.Errorf("%s: fallback remediation is empty", r.ID())
		}
		if len(refs) == 0 {
			t.Errorf("%s: fallback references are empty", r.ID())
		}
	}
}

func TestEnrichRemediation(t *testing.T) {
	findings := []ir.Finding{
		{RuleID: "AEGIS-AWS-001", Title: "S3 bucket without server-side encryption"},
		{RuleID: "AEGIS-AWS-999", Title: "Nonexistent rule"},
	}
	out := EnrichRemediation(findings)
	for i, f := range out {
		if f.Remediation == "" {
			t.Errorf("finding %d (%s): empty remediation after enrich", i, f.RuleID)
		}
		if len(f.References) == 0 {
			t.Errorf("finding %d (%s): empty references after enrich", i, f.RuleID)
		}
	}
}

// TestRemediationFor_NoWrongCloudRefs: no non-AWS rule may ship
// AWS-specific fix steps or links (the multi-cloud audit found 63
// findings with AWS Secrets Manager / CloudTrail / `aws ec2` text on
// Azure, GCP, Terraform, and Kubernetes resources).
func TestRemediationFor_NoWrongCloudRefs(t *testing.T) {
	subMarkers := []string{
		"amazonaws", "cloudtrail", "aws secrets manager", "cis aws",
		"describe-security-groups", "cloudwatch", "elbsecuritypolicy",
		"iam access analyzer",
	}
	wordMarkers := []string{"aws", "arn"}
	for _, r := range DefaultRegistry().All() {
		if strings.HasPrefix(r.ID(), "AEGIS-AWS-") {
			continue
		}
		fix, refs := RemediationFor(r.ID())
		hay := strings.ToLower(fix + " " + strings.Join(refs, " "))
		for _, mk := range subMarkers {
			if strings.Contains(hay, mk) {
				t.Errorf("%s: remediation contains AWS marker %q", r.ID(), mk)
			}
		}
		for _, w := range wordMarkers {
			for _, tok := range strings.FieldsFunc(hay, func(c rune) bool {
				return !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9')
			}) {
				if tok == w {
					t.Errorf("%s: remediation contains AWS word %q", r.ID(), w)
					break
				}
			}
		}
	}
}

// TestRemediationFor_FallbackCloudMatch: fallback guidance for each cloud
// names that cloud's services/docs, not another cloud's.
func TestRemediationFor_FallbackCloudMatch(t *testing.T) {
	cases := []struct {
		id   string
		want []string // must appear in fix or refs (lowercased)
	}{
		{"AEGIS-AZURE-053", []string{"azure", "learn.microsoft.com"}},
		{"AEGIS-GCP-002", []string{"gcloud", "cloud.google.com"}},
		{"AEGIS-K8S-026", []string{"kubernetes", "kubernetes.io"}},
		{"AEGIS-TF-003", []string{"cis"}},
		{"AEGIS-DOCKER-001", []string{"docker", "docs.docker.com"}},
	}
	for _, c := range cases {
		fix, refs := RemediationFor(c.id)
		hay := strings.ToLower(fix + " " + strings.Join(refs, " "))
		for _, w := range c.want {
			if !strings.Contains(hay, w) {
				t.Errorf("%s: fallback should mention %q, got fix=%q refs=%v", c.id, w, fix, refs)
			}
		}
	}
}
