package aws

// Tier 4: Authentication & Supply Chain rules (AEGIS-AWS-521–527).
// Checkov-parity checks targeting auth posture and supply-chain integrity.

import (
	"encoding/json"
	"strings"

	"aegis/internal/ir"
)

// AuthSupplyRules returns the Tier 4 rules in ID order.
func AuthSupplyRules() []ir.Rule {
	return []ir.Rule{
		ecrMutableTags{},            // AEGIS-AWS-521
		neptuneNoIAMAuth{},          // AEGIS-AWS-522
		opensearchNoFGAC{},          // AEGIS-AWS-523
		redshiftDefaultMasterUser{}, // AEGIS-AWS-524
		sagemakerNoAuthMode{},       // AEGIS-AWS-525
		sagemakerPermissivePolicy{}, // AEGIS-AWS-526
		ecsNoReadonlyRootfs{},       // AEGIS-AWS-527
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-521: ECR image tags not immutable (medium)
// ---------------------------------------------------------------------------

type ecrMutableTags struct{}

func (ecrMutableTags) ID() string { return "AEGIS-AWS-521" }
func (ecrMutableTags) Title() string {
	return "ECR repository allows mutable image tags"
}
func (ecrMutableTags) Description() string {
	return "With image_tag_mutability = MUTABLE (the default when absent), " +
		"an attacker who pushes to the repository can overwrite a trusted " +
		"tag such as 'latest' with a malicious image. Set image_tag_mutability " +
		"to IMMUTABLE so tags cannot be overwritten."
}
func (ecrMutableTags) Severity() ir.Severity { return ir.SeverityMedium }
func (ecrMutableTags) AppliesTo(resType string) bool {
	return resType == "aws_ecr_repository"
}
func (ecrMutableTags) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "image_tag_mutability")
	if !present {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-521",
			Title:       (ecrMutableTags{}).Title(),
			Description: (ecrMutableTags{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "image_tag_mutability",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent (defaults to MUTABLE)",
				Expected:  "IMMUTABLE",
			},
		}}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if strings.EqualFold(strings.TrimSpace(val), "MUTABLE") {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-521",
			Title:       (ecrMutableTags{}).Title(),
			Description: (ecrMutableTags{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "image_tag_mutability",
				Span:      evidenceSpan(span, r.Span),
				Actual:    val,
				Expected:  "IMMUTABLE",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-522: Neptune cluster without IAM database authentication (medium)
// ---------------------------------------------------------------------------

type neptuneNoIAMAuth struct{}

func (neptuneNoIAMAuth) ID() string { return "AEGIS-AWS-522" }
func (neptuneNoIAMAuth) Title() string {
	return "Neptune cluster without IAM database authentication"
}
func (neptuneNoIAMAuth) Description() string {
	return "Without iam_database_authentication_enabled, Neptune relies " +
		"solely on master credentials. IAM database authentication adds " +
		"token-based, auditable access control."
}
func (neptuneNoIAMAuth) Severity() ir.Severity { return ir.SeverityMedium }
func (neptuneNoIAMAuth) AppliesTo(resType string) bool {
	return resType == "aws_neptune_cluster"
}
func (neptuneNoIAMAuth) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "iam_database_authentication_enabled")
	if !present {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-522",
			Title:       (neptuneNoIAMAuth{}).Title(),
			Description: (neptuneNoIAMAuth{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "iam_database_authentication_enabled",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent",
				Expected:  "true",
			},
		}}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if !val {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-522",
			Title:       (neptuneNoIAMAuth{}).Title(),
			Description: (neptuneNoIAMAuth{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "iam_database_authentication_enabled",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "false",
				Expected:  "true",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-523: OpenSearch domain without fine-grained access control (medium)
// ---------------------------------------------------------------------------

type opensearchNoFGAC struct{}

func (opensearchNoFGAC) ID() string { return "AEGIS-AWS-523" }
func (opensearchNoFGAC) Title() string {
	return "OpenSearch domain without fine-grained access control"
}
func (opensearchNoFGAC) Description() string {
	return "Without advanced_security_options.enabled, the domain has no " +
		"fine-grained access control: any principal reaching the endpoint " +
		"can read and write any index. Enable fine-grained access control " +
		"with a master user."
}
func (opensearchNoFGAC) Severity() ir.Severity { return ir.SeverityMedium }
func (opensearchNoFGAC) AppliesTo(resType string) bool {
	return resType == "aws_opensearch_domain"
}
func (opensearchNoFGAC) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "advanced_security_options")
	if !present {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-523",
			Title:       (opensearchNoFGAC{}).Title(),
			Description: (opensearchNoFGAC{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "advanced_security_options",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent",
				Expected:  "advanced_security_options block with enabled = true",
			},
		}}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if len(blks) == 0 {
		return nil // empty block list: cannot decide
	}
	b := blks[0]
	enabled, asp, epresent, eknown := blockBool(b, "enabled")
	if epresent && !eknown {
		return nil // unresolved: cannot decide
	}
	if epresent && enabled {
		return nil // fine-grained access control enabled
	}
	actual := "absent"
	if epresent {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-523",
		Title:       (opensearchNoFGAC{}).Title(),
		Description: (opensearchNoFGAC{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "advanced_security_options.enabled",
			Span:      evidenceSpan(asp, r.Span),
			Actual:    actual,
			Expected:  "true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-524: Redshift cluster with default master username (medium)
// ---------------------------------------------------------------------------

type redshiftDefaultMasterUser struct{}

func (redshiftDefaultMasterUser) ID() string { return "AEGIS-AWS-524" }
func (redshiftDefaultMasterUser) Title() string {
	return "Redshift cluster uses default master username"
}
func (redshiftDefaultMasterUser) Description() string {
	return "The default master username 'awsuser' is publicly documented " +
		"and gives attackers half of the credentials for free. Use a " +
		"non-obvious master username."
}
func (redshiftDefaultMasterUser) Severity() ir.Severity { return ir.SeverityMedium }
func (redshiftDefaultMasterUser) AppliesTo(resType string) bool {
	return resType == "aws_redshift_cluster"
}
func (redshiftDefaultMasterUser) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "master_username")
	if !present || !known {
		return nil // absent or unresolved: cannot prove default username
	}
	if strings.EqualFold(strings.TrimSpace(val), "awsuser") {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-524",
			Title:       (redshiftDefaultMasterUser{}).Title(),
			Description: (redshiftDefaultMasterUser{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "master_username",
				Span:      evidenceSpan(span, r.Span),
				Actual:    val,
				Expected:  "non-default username",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-525: SageMaker domain without auth mode restriction (medium)
// ---------------------------------------------------------------------------

type sagemakerNoAuthMode struct{}

func (sagemakerNoAuthMode) ID() string { return "AEGIS-AWS-525" }
func (sagemakerNoAuthMode) Title() string {
	return "SageMaker domain without explicit auth mode"
}
func (sagemakerNoAuthMode) Description() string {
	return "A SageMaker Studio domain with no explicit auth_mode leaves " +
		"authentication posture to provider defaults instead of a " +
		"deliberate SSO or IAM choice. Set auth_mode explicitly (SSO " +
		"preferred) so user access follows a controlled identity path."
}
func (sagemakerNoAuthMode) Severity() ir.Severity { return ir.SeverityMedium }
func (sagemakerNoAuthMode) AppliesTo(resType string) bool {
	return resType == "aws_sagemaker_domain"
}
func (sagemakerNoAuthMode) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "auth_mode")
	if !present {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-525",
			Title:       (sagemakerNoAuthMode{}).Title(),
			Description: (sagemakerNoAuthMode{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "auth_mode",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent",
				Expected:  "SSO or IAM set explicitly",
			},
		}}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	_ = val // any explicit value is a deliberate choice
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-526: IAM policy grants sagemaker:* on * (medium)
// ---------------------------------------------------------------------------

type sagemakerPermissivePolicy struct{}

func (sagemakerPermissivePolicy) ID() string { return "AEGIS-AWS-526" }
func (sagemakerPermissivePolicy) Title() string {
	return "IAM policy grants sagemaker:* on all resources"
}
func (sagemakerPermissivePolicy) Description() string {
	return "An Allow statement with Action sagemaker:* on Resource * hands " +
		"the full SageMaker API — training jobs, endpoints, notebook " +
		"instances, and model artifacts — to every attached principal. " +
		"Scope actions and resources to what the workload needs."
}
func (sagemakerPermissivePolicy) Severity() ir.Severity { return ir.SeverityMedium }
func (sagemakerPermissivePolicy) AppliesTo(resType string) bool {
	return resType == "aws_iam_policy" ||
		resType == "aws_iam_role_policy" ||
		resType == "aws_iam_user_policy" ||
		resType == "aws_iam_group_policy"
}
func (sagemakerPermissivePolicy) Check(r ir.Resource) []ir.Finding {
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if policyAllowsSagemakerStar(doc) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-526",
			Title:       (sagemakerPermissivePolicy{}).Title(),
			Description: (sagemakerPermissivePolicy{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "Allow sagemaker:* on *",
				Expected:  "scoped SageMaker actions and resources",
			},
		}}
	}
	return nil
}

// policyAllowsSagemakerStar reports whether the policy document contains an
// Allow statement with Action sagemaker:* (exact) on Resource *.
func policyAllowsSagemakerStar(doc string) bool {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return false // unparseable: cannot prove
	}
	stmts, ok := parsed["Statement"].([]any)
	if !ok {
		return false
	}
	for _, s := range stmts {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		eff, _ := m["Effect"].(string)
		if !strings.EqualFold(eff, "Allow") {
			continue
		}
		if !sagemakerStringListHas(m["Action"], "sagemaker:*") {
			continue
		}
		if !sagemakerStringListHas(m["Resource"], "*") {
			continue
		}
		return true
	}
	return false
}

// sagemakerStringListHas reports whether v (a string or list of strings) contains
// target (case-insensitive, trimmed).
func sagemakerStringListHas(v any, target string) bool {
	switch t := v.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(t), target)
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && strings.EqualFold(strings.TrimSpace(s), target) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-527: ECS container without read-only root filesystem (medium)
// ---------------------------------------------------------------------------

type ecsNoReadonlyRootfs struct{}

func (ecsNoReadonlyRootfs) ID() string { return "AEGIS-AWS-527" }
func (ecsNoReadonlyRootfs) Title() string {
	return "ECS container without read-only root filesystem"
}
func (ecsNoReadonlyRootfs) Description() string {
	return "A writable container root filesystem lets an attacker who " +
		"gains code execution persist binaries and modify the runtime. " +
		"Set readonlyRootFilesystem to true in container_definitions and " +
		"use volumes for the paths that need writes."
}
func (ecsNoReadonlyRootfs) Severity() ir.Severity { return ir.SeverityMedium }
func (ecsNoReadonlyRootfs) AppliesTo(resType string) bool {
	return resType == "aws_ecs_task_definition"
}
func (ecsNoReadonlyRootfs) Check(r ir.Resource) []ir.Finding {
	raw, span, present, known := getString(r, "container_definitions")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	var defs []map[string]any
	if err := json.Unmarshal([]byte(raw), &defs); err != nil {
		return nil // unparseable JSON: cannot decide
	}
	var out []ir.Finding
	for _, d := range defs {
		ro, ok := d["readonlyRootFilesystem"].(bool)
		if ok && ro {
			continue // explicitly read-only: fine
		}
		name, _ := d["name"].(string)
		detail := "container has writable root filesystem"
		if name != "" {
			detail = "container \"" + name + "\" has writable root filesystem"
		}
		actual := "readonlyRootFilesystem absent"
		if ok {
			actual = "readonlyRootFilesystem = false"
		}
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-AWS-527",
			Title:       (ecsNoReadonlyRootfs{}).Title(),
			Description: (ecsNoReadonlyRootfs{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "container_definitions[].readonlyRootFilesystem",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual + " (" + detail + ")",
				Expected:  "readonlyRootFilesystem = true",
			},
		})
	}
	return out
}
