// Sprint 1–2 regression locks (FP/FN elimination closeout, audit docs
// 24/25/26). Each test pins one Sprint 1 or Sprint 2 fix END TO END —
// real adapter parse -> IR -> full default registry — so the test fails
// if the fix is reverted anywhere in the pipeline, not just inside the
// rule's own unit tests:
//
//   - AEGIS-AWS-858 (Sprint 1): SG database-port exposure, all three
//     Terraform shapes (inline ingress, aws_security_group_rule,
//     aws_vpc_security_group_ingress_rule); silent on port 443.
//   - AEGIS-AZURE-014 (Sprint 1): AKS RBAC via the real ARM/Bicep
//     property spelling `enableRBAC` (the casing bug: the rename table
//     carried `enableRbac`, so the property landed as `enable_rbac`
//     and the rule never fired).
//   - AEGIS-COMPOSE-003/-009 split (Sprint 1): host network is 009,
//     pid/ipc host namespaces are 003 (incl. the ipc extraction the
//     adapter previously dropped).
//   - AEGIS-DOCKER-017/-018 final-stage gating (Sprint 2): image
//     metadata rules judge only the final build stage.
//   - Cross-format parity (Sprint 3 apparatus): public S3 fires
//     AEGIS-AWS-104 from both Terraform and Pulumi; a public storage
//     account produces the identical rule set from ARM and Bicep.
package regression

import (
	"sort"
	"testing"

	"aegis/internal/adapter/arm"
	"aegis/internal/adapter/bicep"
	"aegis/internal/adapter/compose"
	"aegis/internal/adapter/dockerfile"
	"aegis/internal/adapter/pulumi"
	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
	"aegis/internal/rules"
	"aegis/internal/semantics"
)

// scanTFSource parses one Terraform source through the full pipeline
// (adapter -> semantics resolution -> default registry), mirroring
// scanFixture but permitting zero findings for negative cases.
func scanTFSource(t *testing.T, name, src string) []ir.Finding {
	t.Helper()
	mod, diags, err := terraform.New().ParseModule(name, []byte(src))
	if err != nil {
		t.Fatalf("%s: parse hard error: %v", name, err)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("%s: parse error diagnostic: %s", name, d.Message)
		}
	}
	resources := append([]ir.Resource{}, mod.Resources...)
	resources = append(resources, mod.SyntheticResources...)
	scope := semantics.MergeModules([]terraform.Module{mod})
	resources = scope.ResolveResources(resources)
	return rules.DefaultRegistry().Run(resources)
}

type byteParser interface {
	Parse(path string, src []byte) ([]ir.Resource, []ir.Diagnostic, error)
}

// scanParsedSource parses a non-Terraform source with its real adapter
// and runs the full default registry over the resulting resources.
func scanParsedSource(t *testing.T, p byteParser, path, src string) []ir.Finding {
	t.Helper()
	resources, diags, err := p.Parse(path, []byte(src))
	if err != nil {
		t.Fatalf("%s: parse hard error: %v", path, err)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("%s: parse error diagnostic: %s", path, d.Message)
		}
	}
	return rules.DefaultRegistry().Run(resources)
}

func countRule(findings []ir.Finding, id string) int {
	n := 0
	for _, f := range findings {
		if f.RuleID == id {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------
// Sprint 1: AEGIS-AWS-858 — database port exposed to the internet.
// ---------------------------------------------------------------------

const sgDBInlineTF = `
resource "aws_security_group" "db" {
  name = "db"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`

const sgDBRangeTF = `
resource "aws_security_group" "db" {
  name = "db"
  ingress {
    from_port   = 5000
    to_port     = 6000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`

const sgDBStandaloneTF = `
resource "aws_security_group" "db" {
  name = "db"
}

resource "aws_security_group_rule" "db_in" {
  type              = "ingress"
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.db.id
}
`

const sgDBVPCTF = `
resource "aws_security_group" "db" {
  name = "db"
}

resource "aws_vpc_security_group_ingress_rule" "db_in" {
  security_group_id = aws_security_group.db.id
  from_port         = 6379
  to_port           = 6379
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}
`

const sgHTTPSOnlyTF = `
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`

func TestSprintLock_AWS858_DatabasePortForms(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"inline ingress block", sgDBInlineTF},
		{"inline covering port range", sgDBRangeTF},
		{"aws_security_group_rule", sgDBStandaloneTF},
		{"aws_vpc_security_group_ingress_rule", sgDBVPCTF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanTFSource(t, "main.tf", tc.src)
			if got := countRule(findings, "AEGIS-AWS-858"); got != 1 {
				t.Errorf("AEGIS-AWS-858 fired %d times, want exactly 1 (Sprint 1 lock)", got)
			}
		})
	}
	t.Run("https-only ingress stays silent", func(t *testing.T) {
		findings := scanTFSource(t, "main.tf", sgHTTPSOnlyTF)
		if got := countRule(findings, "AEGIS-AWS-858"); got != 0 {
			t.Errorf("AEGIS-AWS-858 fired %d times on port 443, want 0", got)
		}
		if got := countRule(findings, "AEGIS-AWS-004"); got == 0 {
			t.Errorf("sanity: AEGIS-AWS-004 should still fire on world-open 443")
		}
	})
}

// ---------------------------------------------------------------------
// Sprint 1: AEGIS-AZURE-014 — AKS RBAC through the real `enableRBAC`
// spelling, in both ARM JSON and Bicep.
// ---------------------------------------------------------------------

func armAKSTemplate(enableRBAC bool) string {
	v := "false"
	if enableRBAC {
		v = "true"
	}
	return `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.ContainerService/managedClusters",
      "apiVersion": "2024-01-01",
      "name": "lockaks",
      "location": "westeurope",
      "properties": {
        "enableRBAC": ` + v + `,
        "dnsPrefix": "lockaks"
      }
    }
  ]
}`
}

func bicepAKS(enableRBAC bool) string {
	v := "false"
	if enableRBAC {
		v = "true"
	}
	return `
resource aks 'Microsoft.ContainerService/managedClusters@2023-05-01' = {
  name: 'lockaks'
  location: 'westeurope'
  properties: {
    dnsPrefix: 'lockaks'
    enableRBAC: ` + v + `
    agentPoolProfiles: [
      {
        name: 'default'
        count: 1
        vmSize: 'Standard_D2_v2'
        mode: 'System'
      }
    ]
  }
}
`
}

func TestSprintLock_AZURE014_EnableRBACSpelling(t *testing.T) {
	t.Run("ARM enableRBAC=false fires", func(t *testing.T) {
		findings := scanParsedSource(t, arm.New(), "azuredeploy.json", armAKSTemplate(false))
		if got := countRule(findings, "AEGIS-AZURE-014"); got != 1 {
			t.Errorf("AEGIS-AZURE-014 fired %d times on ARM enableRBAC=false, want 1 (casing-bug lock)", got)
		}
	})
	t.Run("ARM enableRBAC=true silent", func(t *testing.T) {
		findings := scanParsedSource(t, arm.New(), "azuredeploy.json", armAKSTemplate(true))
		if got := countRule(findings, "AEGIS-AZURE-014"); got != 0 {
			t.Errorf("AEGIS-AZURE-014 fired %d times on ARM enableRBAC=true, want 0", got)
		}
	})
	t.Run("Bicep enableRBAC=false fires", func(t *testing.T) {
		findings := scanParsedSource(t, bicep.New(), "main.bicep", bicepAKS(false))
		if got := countRule(findings, "AEGIS-AZURE-014"); got != 1 {
			t.Errorf("AEGIS-AZURE-014 fired %d times on Bicep enableRBAC=false, want 1 (casing-bug lock)", got)
		}
	})
	t.Run("Bicep enableRBAC=true silent", func(t *testing.T) {
		findings := scanParsedSource(t, bicep.New(), "main.bicep", bicepAKS(true))
		if got := countRule(findings, "AEGIS-AZURE-014"); got != 0 {
			t.Errorf("AEGIS-AZURE-014 fired %d times on Bicep enableRBAC=true, want 0", got)
		}
	})
}

// ---------------------------------------------------------------------
// Sprint 1: COMPOSE-003 / COMPOSE-009 split (+ ipc extraction).
// ---------------------------------------------------------------------

func TestSprintLock_ComposeHostNamespaceSplit(t *testing.T) {
	cases := []struct {
		name    string
		snippet string
		want003 int
		want009 int
	}{
		{"network_mode only", "    network_mode: host\n", 0, 1},
		{"pid only", "    pid: host\n", 1, 0},
		{"ipc only", "    ipc: host\n", 1, 0},
		{"network_mode and pid", "    network_mode: host\n    pid: host\n", 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "services:\n  monitor:\n    image: registry.example.com/monitor:1.9.0\n" + tc.snippet
			findings := scanParsedSource(t, compose.New(), "docker-compose.yml", src)
			if got := countRule(findings, "AEGIS-COMPOSE-003"); got != tc.want003 {
				t.Errorf("AEGIS-COMPOSE-003 fired %d times, want %d (003 = pid/ipc only after the split)", got, tc.want003)
			}
			if got := countRule(findings, "AEGIS-COMPOSE-009"); got != tc.want009 {
				t.Errorf("AEGIS-COMPOSE-009 fired %d times, want %d (009 = host network)", got, tc.want009)
			}
		})
	}
}

// ---------------------------------------------------------------------
// Sprint 2: DOCKER-017/-018 judge only the final build stage.
// ---------------------------------------------------------------------

const dockerTwoStageClean = `FROM golang:1.23 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app .

FROM alpine:3.20
LABEL maintainer="team@example.com"
WORKDIR /app
COPY --from=build /out/app /app
USER 10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["/app"]
`

const dockerTwoStageDirtyFinal = `FROM golang:1.23 AS build
WORKDIR /src
RUN go build -o /out/app .

FROM alpine:3.20
COPY --from=build /out/app /app
ENTRYPOINT ["/app"]
`

func TestSprintLock_DockerFinalStageGating(t *testing.T) {
	t.Run("violations confined to build stage stay silent", func(t *testing.T) {
		findings := scanParsedSource(t, dockerfile.New(), "Dockerfile", dockerTwoStageClean)
		if got := countRule(findings, "AEGIS-DOCKER-017"); got != 0 {
			t.Errorf("AEGIS-DOCKER-017 fired %d times, want 0 (final stage carries the label)", got)
		}
		if got := countRule(findings, "AEGIS-DOCKER-018"); got != 0 {
			t.Errorf("AEGIS-DOCKER-018 fired %d times, want 0 (final stage carries STOPSIGNAL)", got)
		}
	})
	t.Run("dirty final stage fires exactly once each", func(t *testing.T) {
		findings := scanParsedSource(t, dockerfile.New(), "Dockerfile", dockerTwoStageDirtyFinal)
		if got := countRule(findings, "AEGIS-DOCKER-017"); got != 1 {
			t.Errorf("AEGIS-DOCKER-017 fired %d times, want exactly 1 (final stage only; build stage is gated)", got)
		}
		if got := countRule(findings, "AEGIS-DOCKER-018"); got != 1 {
			t.Errorf("AEGIS-DOCKER-018 fired %d times, want exactly 1 (final stage only; build stage is gated)", got)
		}
	})
}

// ---------------------------------------------------------------------
// Sprint 3 parity locks: one canonical vulnerability, one rule ID,
// across formats.
// ---------------------------------------------------------------------

func TestSprintLock_Parity_PublicS3_TerraformAndPulumi(t *testing.T) {
	tf := scanTFSource(t, "main.tf", `
resource "aws_s3_bucket" "vuln" {
  acl = "public-read"
}
`)
	if got := countRule(tf, "AEGIS-AWS-104"); got == 0 {
		t.Errorf("Terraform public S3: AEGIS-AWS-104 did not fire")
	}
	pulumiSrc := `name: parity-public
runtime: yaml
resources:
  dataBucket:
    type: aws:s3:Bucket
    properties:
      bucket: parity-public-data
      acl: public-read
`
	pl := scanParsedSource(t, pulumi.Adapter{}, "Pulumi.yaml", pulumiSrc)
	if got := countRule(pl, "AEGIS-AWS-104"); got == 0 {
		t.Errorf("Pulumi public S3: AEGIS-AWS-104 did not fire (cross-format parity break)")
	}
}

const armStoragePublic = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "paritypublicst",
      "location": "westeurope",
      "sku": { "name": "Standard_LRS" },
      "kind": "StorageV2",
      "properties": {
        "allowBlobPublicAccess": true
      }
    }
  ]
}`

const bicepStoragePublic = `
resource st 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'paritypublicst'
  location: 'westeurope'
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
  }
}
`

func ruleIDSet(findings []ir.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			out = append(out, f.RuleID)
		}
	}
	sort.Strings(out)
	return out
}

func TestSprintLock_Parity_StoragePublic_ARMAndBicep(t *testing.T) {
	armFindings := scanParsedSource(t, arm.New(), "azuredeploy.json", armStoragePublic)
	bicepFindings := scanParsedSource(t, bicep.New(), "main.bicep", bicepStoragePublic)
	armSet := ruleIDSet(armFindings)
	bicepSet := ruleIDSet(bicepFindings)
	if len(armSet) != len(bicepSet) {
		t.Fatalf("ARM/Bicep rule sets differ in size: ARM=%v Bicep=%v", armSet, bicepSet)
	}
	for i := range armSet {
		if armSet[i] != bicepSet[i] {
			t.Fatalf("ARM/Bicep rule sets differ: ARM=%v Bicep=%v", armSet, bicepSet)
		}
	}
	found := false
	for _, id := range armSet {
		if id == "AEGIS-AZURE-031" {
			found = true
		}
	}
	if !found {
		t.Errorf("canonical storage-public rule AEGIS-AZURE-031 missing from ARM/Bicep set %v", armSet)
	}
}
