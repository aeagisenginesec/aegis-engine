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
				return (c < 'a' || c > 'z') && (c < '0' || c > '9')
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

// TestRemediationFor_AuditCorrections pins the remediation fixes from the
// multi-cloud quality audit follow-up: each rule must now receive fix steps
// that actually resolve the finding (not a keyword-mismatched template).
func TestRemediationFor_AuditCorrections(t *testing.T) {
	cases := map[string]string{
		"AEGIS-AWS-310":   "monitoring = true",
		"AEGIS-AWS-311":   "iam_database_authentication_enabled = true",
		"AEGIS-AWS-546":   "copy_tags_to_snapshot = true",
		"AEGIS-AWS-605":   "monitoring_interval",
		"AEGIS-AWS-667":   "permissions_boundary",
		"AEGIS-AWS-673":   "description",
		"AEGIS-AZURE-046": "security_alert_policy",
		"AEGIS-AZURE-125": "sas_policy",
		"AEGIS-AZURE-186": "soft_delete_retention_days = 90",
		"AEGIS-GCP-060":   "enable-oslogin",
	}
	for id, want := range cases {
		fix, _ := RemediationFor(id)
		if !strings.Contains(fix, want) {
			t.Errorf("%s: remediation should prescribe %q, got: %.120q", id, want, fix)
		}
	}
}

// TestRemediationFor_GCP060NotAuditLogging: the "login" in "OS Login" must
// not route to the audit-logging template (substring collision).
func TestRemediationFor_GCP060NotAuditLogging(t *testing.T) {
	fix, _ := RemediationFor("AEGIS-GCP-060")
	if strings.Contains(strings.ToLower(fix), "cloud audit logs") {
		t.Errorf("AEGIS-GCP-060 must not receive audit-logging guidance, got: %.120q", fix)
	}
}

// TestRemediationFor_GCP030BucketValid: the deletion-protection fallback
// must not prescribe `deletion_protection` for GCS buckets (invalid arg).
func TestRemediationFor_GCP030BucketValid(t *testing.T) {
	fix, _ := RemediationFor("AEGIS-GCP-030")
	if strings.Contains(fix, "on databases, instances, and buckets") {
		t.Errorf("AEGIS-GCP-030 must not claim deletion_protection works on buckets, got: %.200q", fix)
	}
	if !strings.Contains(fix, "force_destroy") {
		t.Errorf("AEGIS-GCP-030 should mention force_destroy, got: %.200q", fix)
	}
}

// TestRemediationFor_Azure032NoAWSAttr: the Azure encrypt fallback must not
// cite the AWS RDS attribute `storage_encrypted`.
func TestRemediationFor_Azure032NoAWSAttr(t *testing.T) {
	fix, _ := RemediationFor("AEGIS-AZURE-032")
	if strings.Contains(fix, "storage_encrypted") {
		t.Errorf("AEGIS-AZURE-032 must not cite AWS attribute storage_encrypted, got: %.200q", fix)
	}
}
