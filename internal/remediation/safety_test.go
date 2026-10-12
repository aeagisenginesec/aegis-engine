// Phase 4 Workstream 4 — remediation safety validation.
//
// TestComplexFilePatchesReparse: every shipped fixer is run against a
// complex, realistic Terraform file (variables, locals, dynamic blocks,
// VPC, SG with multiple ingress blocks, IAM role + policy, RDS, S3, EBS,
// CloudTrail). Every proposed patch is applied and the result re-parsed
// with the real terraform adapter: zero error diagnostics, and the target
// resource must still exist.
//
// TestBlockedResourceTypesGate: the dangerous-resource blocklist. Probe
// fixers (which simulate a future fixer that would touch IAM policy or
// SG rules) propose nothing without AllowBlocked and propose with
// AllowBlocked=true.
package remediation

import (
	"os"
	"strings"
	"testing"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
)

// complexSafetySrc is deliberately messy the way real Terraform is:
// variables, locals, dynamic blocks, multi-line jsonencode policies, and a
// security group with static + dynamic ingress blocks.
const complexSafetySrc = `terraform {
  required_version = ">= 1.5"
}

variable "env" {
  description = "Deployment environment"
  type        = string
  default     = "prod"
}

variable "extra_ports" {
  description = "Additional ports to open on the web SG"
  type        = list(number)
  default     = [8080, 8443]
}

locals {
  name_prefix = "aegis-${var.env}"
  common_tags = {
    ManagedBy = "aegis"
    Env       = var.env
  }
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-vpc" })
}

resource "aws_security_group" "web" {
  name        = "${local.name_prefix}-web"
  description = "Web tier security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS - overly open"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH - overly open"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "ingress" {
    for_each = var.extra_ports
    content {
      description = "extra port"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/8"]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_iam_role" "app" {
  name = "${local.name_prefix}-app"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_policy" "app" {
  name = "${local.name_prefix}-app"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      },
    ]
  })
}

resource "aws_s3_bucket" "logs" {
  bucket = "${local.name_prefix}-logs"
  acl    = "public-read"

  tags = local.common_tags
}

resource "aws_db_instance" "main" {
  identifier          = "${local.name_prefix}-db"
  engine              = "postgres"
  instance_class      = "db.t4g.micro"
  allocated_storage   = 20
  storage_encrypted   = false
  deletion_protection = false
  publicly_accessible = true
  skip_final_snapshot = true

  tags = local.common_tags
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false

  tags = local.common_tags
}

resource "aws_cloudtrail" "audit" {
  name                          = "${local.name_prefix}-audit"
  s3_bucket_name                = aws_s3_bucket.logs.id
  include_global_service_events = true
  enable_log_file_validation    = false
}
`

func parseSafetyFile(t *testing.T, src string) []ir.Resource {
	t.Helper()
	res, diags, err := terraform.New().Parse("main.tf", []byte(src))
	if err != nil {
		t.Fatalf("terraform adapter Parse failed: %v", err)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("error diagnostic parsing safety fixture: %s (line %d)", d.Message, d.Span.StartLine)
		}
	}
	return res
}

func findSafetyResource(t *testing.T, resources []ir.Resource, addr string) ir.Resource {
	t.Helper()
	for _, r := range resources {
		if r.Address() == addr {
			return r
		}
	}
	t.Fatalf("resource %s not found in parsed fixture", addr)
	return ir.Resource{}
}

// safetyFinding builds a finding whose evidence span comes from the parsed
// resource itself (attribute value span, or the whole resource span for
// block-level findings), mirroring what the rules engine emits.
func safetyFinding(t *testing.T, resources []ir.Resource, ruleID, addr, attr string) ir.Finding {
	t.Helper()
	res := findSafetyResource(t, resources, addr)
	span := res.Span
	if attr != "" {
		v, ok := res.Attr(attr)
		if !ok {
			t.Fatalf("attr %q missing on %s", attr, addr)
		}
		span = v.Span
	}
	return ir.Finding{
		RuleID:   ruleID,
		Resource: addr,
		Evidence: ir.Evidence{Attribute: attr, Span: span},
	}
}

func safetyReadFile(path string) ([]byte, error) {
	if path == "main.tf" {
		return []byte(complexSafetySrc), nil
	}
	return nil, os.ErrNotExist
}

// assertPatchReparsesCleanly applies one patch to the fixture source,
// re-parses with the real terraform adapter, and requires zero error
// diagnostics and that the target resource still exists.
func assertPatchReparsesCleanly(t *testing.T, p Patch) {
	t.Helper()
	patched, err := ApplyEdits(complexSafetySrc, p.Edits)
	if err != nil {
		t.Fatalf("ApplyEdits failed for %s/%s: %v", p.RuleID, p.Resource, err)
	}
	res2, diags, err := terraform.New().Parse("main.tf", []byte(patched))
	if err != nil {
		t.Fatalf("patched file for %s/%s does not parse: %v", p.RuleID, p.Resource, err)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Errorf("error diagnostic after patch %s/%s: %s (line %d)",
				p.RuleID, p.Resource, d.Message, d.Span.StartLine)
		}
	}
	found := false
	for _, r := range res2 {
		if r.Address() == p.Resource {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("target resource %s missing after patch %s (file corrupted?)", p.Resource, p.RuleID)
	}
	if !strings.Contains(p.Diff, "@@") {
		t.Errorf("patch %s/%s has no rendered diff", p.RuleID, p.Resource)
	}
}

func TestComplexFilePatchesReparse(t *testing.T) {
	resources := parseSafetyFile(t, complexSafetySrc)
	findings := []ir.Finding{
		safetyFinding(t, resources, "AEGIS-AWS-001", "aws_s3_bucket.logs", ""),
		safetyFinding(t, resources, "AEGIS-AWS-002", "aws_s3_bucket.logs", "acl"),
		safetyFinding(t, resources, "AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted"),
		safetyFinding(t, resources, "AEGIS-AWS-008", "aws_db_instance.main", "deletion_protection"),
		safetyFinding(t, resources, "AEGIS-AWS-011", "aws_db_instance.main", "publicly_accessible"),
		safetyFinding(t, resources, "AEGIS-AWS-009", "aws_ebs_volume.data", "encrypted"),
		safetyFinding(t, resources, "AEGIS-AWS-010", "aws_cloudtrail.audit", "enable_log_file_validation"),
		safetyFinding(t, resources, "AEGIS-AWS-012", "aws_s3_bucket.logs", ""),
		// No fixer exists for these, and they sit on blocked types:
		// nothing may ever be proposed for them by DefaultFixers.
		safetyFinding(t, resources, "AEGIS-AWS-004", "aws_security_group.web", ""),
		safetyFinding(t, resources, "AEGIS-AWS-006", "aws_iam_policy.app", "policy"),
		safetyFinding(t, resources, "AEGIS-AWS-006", "aws_iam_role.app", "assume_role_policy"),
	}
	patches := proposeAllWithFixers(findings, resources, safetyReadFile, DefaultFixers())
	if len(patches) != 8 {
		t.Fatalf("want 8 patches (one per fixable rule), got %d", len(patches))
	}
	for _, p := range patches {
		if p.RuleID == "AEGIS-AWS-004" || p.RuleID == "AEGIS-AWS-006" {
			t.Errorf("patch proposed for human-judgment rule %s on %s", p.RuleID, p.Resource)
		}
		assertPatchReparsesCleanly(t, p)
	}
}

// dangerFixer is a test-only fixer that proposes patches on BLOCKED
// resource types, simulating a future fixer that would touch an IAM policy
// or a security-group rule. It exists solely to prove the ProposeAll
// blocklist gate (safety.go) actually fires. (One fixer per rule ID, like
// the real fixers.)
type dangerFixer struct {
	ruleID   string
	resTypes map[string]bool
}

func (d dangerFixer) RuleID() string { return d.ruleID }

func (d dangerFixer) Propose(f ir.Finding, res ir.Resource, src []byte) []Patch {
	if !d.resTypes[res.Type] {
		return nil
	}
	edit, ok := insertAttrBeforeClose(src, res, "aegis_danger_probe", "true")
	if !ok {
		return nil
	}
	return []Patch{withDiff(Patch{
		RuleID:      d.ruleID,
		Resource:    res.Address(),
		Description: "TEST-ONLY probe patch on a blocked resource type",
		Edits:       []Edit{edit},
	}, src)}
}

func TestBlockedResourceTypesGate(t *testing.T) {
	t.Cleanup(func() { AllowBlocked = false })

	// The table must contain every type the mission names, and nothing
	// fixable may be on it.
	for _, typ := range []string{
		"aws_iam_policy", "aws_iam_role_policy", "aws_iam_group_policy",
		"aws_iam_user_policy", "aws_iam_role", "aws_security_group",
		"aws_security_group_rule", "aws_vpc_security_group_ingress_rule",
		"aws_vpc_security_group_egress_rule", "aws_network_acl",
	} {
		if !IsBlocked(typ) {
			t.Errorf("expected %s to be blocked", typ)
		}
	}
	for _, typ := range []string{
		"aws_s3_bucket", "aws_s3_bucket_acl", "aws_db_instance",
		"aws_ebs_volume", "aws_cloudtrail", "aws_vpc",
	} {
		if IsBlocked(typ) {
			t.Errorf("expected %s NOT to be blocked", typ)
		}
	}

	resources := parseSafetyFile(t, complexSafetySrc)
	findings := []ir.Finding{
		safetyFinding(t, resources, "AEGIS-AWS-004", "aws_security_group.web", ""),
		safetyFinding(t, resources, "AEGIS-AWS-006", "aws_iam_policy.app", "policy"),
		safetyFinding(t, resources, "AEGIS-AWS-006", "aws_iam_role.app", "assume_role_policy"),
		// A control: this one must be proposed regardless of the flag.
		safetyFinding(t, resources, "AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted"),
	}
	fixers := append(DefaultFixers(),
		dangerFixer{ruleID: "AEGIS-AWS-004", resTypes: map[string]bool{"aws_security_group": true}},
		dangerFixer{ruleID: "AEGIS-AWS-006", resTypes: map[string]bool{"aws_iam_policy": true, "aws_iam_role": true}},
	)

	// Default: blocked findings are skipped even though fixers exist for
	// them; the control patch is still proposed.
	AllowBlocked = false
	blocked := proposeAllWithFixers(findings, resources, safetyReadFile, fixers)
	if len(blocked) != 1 {
		t.Fatalf("want only the 007 control patch with AllowBlocked=false, got %d", len(blocked))
	}
	if blocked[0].RuleID != "AEGIS-AWS-007" {
		t.Errorf("unexpected patch with AllowBlocked=false: %+v", blocked[0])
	}
	for _, p := range blocked {
		if p.RuleID == "AEGIS-AWS-004" || p.RuleID == "AEGIS-AWS-006" {
			t.Errorf("blocklist bypassed: patch for %s on %s", p.RuleID, p.Resource)
		}
	}

	// Opt-in: patches ARE proposed for the blocked findings too.
	AllowBlocked = true
	unblocked := proposeAllWithFixers(findings, resources, safetyReadFile, fixers)
	if len(unblocked) != 4 {
		t.Fatalf("want 4 patches with AllowBlocked=true, got %d", len(unblocked))
	}
	seen := map[string]bool{}
	for _, p := range unblocked {
		seen[p.RuleID+"/"+p.Resource] = true
		assertPatchReparsesCleanly(t, p)
	}
	for _, want := range []string{
		"AEGIS-AWS-004/aws_security_group.web",
		"AEGIS-AWS-006/aws_iam_policy.app",
		"AEGIS-AWS-006/aws_iam_role.app",
		"AEGIS-AWS-007/aws_db_instance.main",
	} {
		if !seen[want] {
			t.Errorf("expected patch %s with AllowBlocked=true", want)
		}
	}
}
