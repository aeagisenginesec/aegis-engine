// Combat-corpus test (mission/accuracy-100): the 26-resource fixture in
// testdata/combat_vuln.tf carries 15 vulnerable controls and 11 secure
// controls. Scoring is PER CONTROL, not raw finding counts: a secure
// control passes when the negation of its vulnerable counterpart does
// not fire. Secure resources legitimately carry OTHER findings
// (absent-hardening rules), which are factually true and are NOT false
// positives on the control — e.g. aws_db_instance.privdb fires backup
// / Multi-AZ hygiene rules, and google_storage_bucket.secb fires
// "without public access prevention" because public_access_prevention
// really is absent even though uniform_bucket_level_access is on.
// Those are listed in the test output for auditability but do not fail
// the test. What would fail is the control's own negation firing.
package regression

import (
	"sort"
	"testing"
)

type combatControl struct {
	resource string
	// required: at least one of these must fire (vulnerable controls).
	required []string
	// forbidden: none of these may fire (secure controls).
	forbidden []string
}

var combatVulnerable = []combatControl{
	{"aws_s3_bucket.pub", []string{"AEGIS-AWS-002"}, nil},
	{"aws_security_group.open", []string{"AEGIS-AWS-004"}, nil},
	{"aws_db_instance.pubdb", []string{"AEGIS-AWS-011"}, nil},
	{"aws_iam_policy.admin", []string{"AEGIS-AWS-006"}, nil},
	{"aws_ebs_volume.unenc", []string{"AEGIS-AWS-009"}, nil},
	{"aws_kms_key.norot", []string{"AEGIS-AWS-335"}, nil},
	{"aws_cloudtrail.single", []string{"AEGIS-AWS-336"}, nil},
	{"azurerm_storage_account.pubst", []string{"AEGIS-AZR-001", "AEGIS-AZURE-122"}, nil},
	{"azurerm_key_vault.nopurge", []string{"AEGIS-AZR-005"}, nil},
	{"azurerm_sql_server.weak", []string{"AEGIS-AZURE-314"}, nil},
	{"azurerm_network_security_group.opennsg", []string{"AEGIS-AZURE-054", "AEGIS-AZURE-244"}, nil},
	{"google_storage_bucket.pubb", []string{"AEGIS-GCP-005"}, nil},
	{"google_compute_firewall.openfw", []string{"AEGIS-GCP-002"}, nil},
	{"google_sql_database_instance.nolog", []string{"AEGIS-GCP-019"}, nil},
	{"google_compute_instance.pubvm", []string{"AEGIS-GCP-017"}, nil},
}

var combatSecure = []combatControl{
	{"aws_s3_bucket.priv", nil, []string{"AEGIS-AWS-002", "AEGIS-AWS-003"}},
	{"aws_security_group.closed", nil, []string{"AEGIS-AWS-004"}},
	{"aws_db_instance.privdb", nil, []string{"AEGIS-AWS-011", "AEGIS-AWS-007", "AEGIS-AWS-008"}},
	{"aws_iam_policy.readonly", nil, []string{"AEGIS-AWS-006", "AEGIS-AWS-102", "AEGIS-AWS-501"}},
	{"aws_ebs_volume.enc", nil, []string{"AEGIS-AWS-009"}},
	{"azurerm_storage_account.secst", nil, []string{"AEGIS-AZR-001", "AEGIS-AZURE-122", "AEGIS-AZURE-121"}},
	{"azurerm_key_vault.purged", nil, []string{"AEGIS-AZR-005"}},
	{"azurerm_network_security_group.closednsg", nil, []string{"AEGIS-AZURE-054", "AEGIS-AZURE-244"}},
	{"google_storage_bucket.secb", nil, []string{"AEGIS-GCP-005", "AEGIS-GCP-016"}},
	{"google_compute_firewall.closedfw", nil, []string{"AEGIS-GCP-002"}},
	{"google_compute_instance.privvm", nil, []string{"AEGIS-GCP-017"}},
}

func TestCombat(t *testing.T) {
	findings := scanFixture(t, "combat_vuln.tf")
	fired := map[string]map[string]bool{}
	for _, f := range findings {
		if fired[f.Resource] == nil {
			fired[f.Resource] = map[string]bool{}
		}
		fired[f.Resource][f.RuleID] = true
	}
	caught := 0
	for _, c := range combatVulnerable {
		hit := false
		for _, id := range c.required {
			if fired[c.resource][id] {
				hit = true
			}
		}
		if !hit {
			t.Errorf("vulnerable control %s: none of %v fired (got %v)",
				c.resource, c.required, keysOf(fired[c.resource]))
			continue
		}
		caught++
	}
	t.Logf("combat vulnerable controls caught: %d/15", caught)
	fp := 0
	for _, c := range combatSecure {
		for _, id := range c.forbidden {
			if fired[c.resource][id] {
				t.Errorf("secure control %s: forbidden rule %s fired (false positive)", c.resource, id)
				fp++
			}
		}
		others := []string{}
		for id := range fired[c.resource] {
			if !contains(c.forbidden, id) {
				others = append(others, id)
			}
		}
		sort.Strings(others)
		t.Logf("secure %s: other (non-control) findings: %v", c.resource, others)
	}
	t.Logf("combat secure-control false positives: %d (want 0)", fp)
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
