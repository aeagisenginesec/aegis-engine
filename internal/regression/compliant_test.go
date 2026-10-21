package regression

// Sprint 3 compliant-code FP budget (Plan 24, Part 2 item 2): the
// fixtures under testdata/compliant/ are projects configured the
// secure way — private, encrypted, RBAC on, TLS enforced, logging
// on, no world-open ingress. Scanning them with the FULL engine must
// produce ZERO findings from active non-hygiene rules. The hygiene
// IDs below are the evaluation's documented exclusions (signal vs
// noise bookkeeping, mirrored from the R4 scorer at
// docs/audit/raw/final-eval-r4/score.py HYGIENE_RULE_IDS); at the
// time this gate was written the fixtures produce zero findings in
// total, hygiene included.
//
// Building these fixtures caught real adapter bugs, all fixed with
// twin tests in their packages (internal/adapter/arm,
// internal/adapter/bicep): blobServices/queueServices children
// mis-mapped onto phantom storage accounts with an unreachable fold,
// the defaultToOAuthAuthentication snake-case mangling, sasPolicy /
// customer-managed-key block translation, literal resourceId()
// references degrading to Unknown, Bicep resource .id references,
// and VNet dhcpOptions DNS flattening.

import (
	"os"
	"path/filepath"
	"testing"

	"aegis/internal/adapter/arm"
	"aegis/internal/adapter/bicep"
	"aegis/internal/adapter/compose"
	"aegis/internal/adapter/dockerfile"
	"aegis/internal/adapter/manifests"
	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
	"aegis/internal/rules"
)

var hygieneRuleIDs = map[string]bool{
	"AEGIS-AWS-706": true, "AEGIS-AZURE-111": true, "AEGIS-GCP-215": true,
	"AEGIS-TF-004": true, "AEGIS-AWS-658": true, "AEGIS-AWS-684": true,
	"AEGIS-AWS-798": true, "AEGIS-GCP-114": true, "AEGIS-AWS-699": true,
}

func compliantFixture(t *testing.T, rel string) (string, []byte) {
	t.Helper()
	p := filepath.Join("testdata", "compliant", rel)
	src, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, src
}

func TestCompliantFixturesZeroBudget(t *testing.T) {
	reg := rules.DefaultRegistry()
	cases := []struct {
		name  string
		parse func(t *testing.T) []ir.Resource
	}{
		{"terraform", func(t *testing.T) []ir.Resource {
			p, src := compliantFixture(t, "terraform/main.tf")
			res, _, err := terraform.New().Parse(p, src)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}},
		{"arm", func(t *testing.T) []ir.Resource {
			p, src := compliantFixture(t, "arm/azuredeploy.json")
			res, _, err := arm.New().Parse(p, src)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}},
		{"bicep", func(t *testing.T) []ir.Resource {
			p, src := compliantFixture(t, "bicep/main.bicep")
			res, _, err := bicep.New().Parse(p, src)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}},
		{"k8s", func(t *testing.T) []ir.Resource {
			p, src := compliantFixture(t, "k8s/manifests.yaml")
			res, _, err := manifests.Adapter{}.Parse(p, src)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}},
		{"compose", func(t *testing.T) []ir.Resource {
			p, src := compliantFixture(t, "compose/docker-compose.yml")
			res, _, err := compose.New().Parse(p, src)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}},
		{"dockerfile", func(t *testing.T) []ir.Resource {
			p, src := compliantFixture(t, "dockerfile/Dockerfile")
			res, _, err := dockerfile.New().Parse(p, src)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := c.parse(t)
			if len(res) == 0 {
				t.Fatalf("fixture produced no resources; gate would be vacuous")
			}
			findings := reg.Run(res)
			var offenders []ir.Finding
			for _, f := range findings {
				if !hygieneRuleIDs[f.RuleID] {
					offenders = append(offenders, f)
				}
			}
			if len(offenders) > 0 {
				for _, f := range offenders {
					t.Errorf("compliant fixture tripped %s on %s: %s",
						f.RuleID, f.Resource, f.Evidence)
				}
				t.Fatalf("%d non-hygiene findings on compliant %s fixture "+
					"(FP budget is 0)", len(offenders), c.name)
			}
		})
	}
}
