package aws

// Coverage gap rules (AEGIS-AWS-552–571): top-20 gaps from the coverage matrix.
// Organized by service area: IAM (552-555), Networking (556-557), S3 (558-560),
// KMS/Secrets (561-563), Compute (564-565), Databases (566), Logging (567-570),
// Supply Chain (571).

import (
	"encoding/json"
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-552: IAM access key without PGP encryption
// ---------------------------------------------------------------------------

type iamAccessKeyNoPGP struct{}

func (iamAccessKeyNoPGP) ID() string { return "AEGIS-AWS-552" }
func (iamAccessKeyNoPGP) Title() string {
	return "IAM access key created without PGP encryption"
}
func (iamAccessKeyNoPGP) Description() string {
	return "IAM access keys should be created with pgp_key so the secret " +
		"access key is encrypted at creation. Without it, the plaintext " +
		"secret is stored in Terraform state. Set pgp_key to a PGP public key."
}
func (iamAccessKeyNoPGP) Severity() ir.Severity { return ir.SeverityHigh }
func (iamAccessKeyNoPGP) AppliesTo(resType string) bool {
	return resType == "aws_iam_access_key"
}
func (iamAccessKeyNoPGP) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "pgp_key")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-552",
			Title:       (iamAccessKeyNoPGP{}).Title(),
			Description: (iamAccessKeyNoPGP{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "pgp_key",
				Span:      evidenceSpan(ir.Span{}, r.Span),
				Actual:    "absent",
				Expected:  "pgp_key set to a PGP public key",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-553: IAM policy with NotAction + Allow (deny-bypass)
// ---------------------------------------------------------------------------

type iamPolicyNotActionAllow struct{}

func (iamPolicyNotActionAllow) ID() string { return "AEGIS-AWS-553" }
func (iamPolicyNotActionAllow) Title() string {
	return "IAM policy uses NotAction with Allow effect"
}
func (iamPolicyNotActionAllow) Description() string {
	return "Combining \"NotAction\" with \"Effect\": \"Allow\" creates a " +
		"deny-bypass pattern: the policy allows everything EXCEPT the " +
		"listed actions, which is the inverse of least privilege. Rewrite " +
		"using explicit Action lists."
}
func (iamPolicyNotActionAllow) Severity() ir.Severity { return ir.SeverityHigh }
func (iamPolicyNotActionAllow) AppliesTo(resType string) bool {
	return resType == "aws_iam_policy" ||
		resType == "aws_iam_role_policy" ||
		resType == "aws_iam_user_policy" ||
		resType == "aws_iam_group_policy"
}
func (iamPolicyNotActionAllow) Check(r ir.Resource) []ir.Finding {
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // unresolved or absent: cannot decide
	}
	if policyHasNotActionAllow(doc) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-553",
			Title:       (iamPolicyNotActionAllow{}).Title(),
			Description: (iamPolicyNotActionAllow{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "NotAction with Allow effect",
				Expected:  "explicit Action lists (no NotAction with Allow)",
			},
		}}
	}
	return nil
}

// policyHasNotActionAllow reports whether a policy JSON document contains a
// statement with Effect Allow and a NotAction element.
func policyHasNotActionAllow(doc string) bool {
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
		if _, has := m["NotAction"]; has {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-554: IAM role with excessive max session duration
// ---------------------------------------------------------------------------

type iamRoleLongSession struct{}

func (iamRoleLongSession) ID() string { return "AEGIS-AWS-554" }
func (iamRoleLongSession) Title() string {
	return "IAM role with max session duration over 12 hours"
}
func (iamRoleLongSession) Description() string {
	return "IAM roles should limit max_session_duration to 12 hours " +
		"(43200 seconds) or less. Longer sessions increase the window for " +
		"credential misuse if temporary credentials are compromised. " +
		"Set max_session_duration <= 43200."
}
func (iamRoleLongSession) Severity() ir.Severity { return ir.SeverityMedium }
func (iamRoleLongSession) AppliesTo(resType string) bool {
	return resType == "aws_iam_role"
}
func (iamRoleLongSession) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getNumber(r, "max_session_duration")
	if !present || !known {
		return nil // absent (default 3600) or unresolved: cannot decide
	}
	if val > 43200 {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-554",
			Title:       (iamRoleLongSession{}).Title(),
			Description: (iamRoleLongSession{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "max_session_duration",
				Span:      evidenceSpan(span, r.Span),
				Actual:    strconv.FormatFloat(val, 'f', -1, 64),
				Expected:  "max_session_duration <= 43200",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-555: IAM group inline policy with wildcard admin
// ---------------------------------------------------------------------------

type iamGroupAdminPolicy struct{}

func (iamGroupAdminPolicy) ID() string { return "AEGIS-AWS-555" }
func (iamGroupAdminPolicy) Title() string {
	return "IAM group inline policy grants wildcard admin"
}
func (iamGroupAdminPolicy) Description() string {
	return "IAM group inline policies should not grant \"Action\": \"*\" " +
		"on \"Resource\": \"*\". Group membership changes silently expand " +
		"the blast radius. Use managed policies with scoped permissions instead."
}
func (iamGroupAdminPolicy) Severity() ir.Severity { return ir.SeverityMedium }
func (iamGroupAdminPolicy) AppliesTo(resType string) bool {
	return resType == "aws_iam_group_policy"
}
func (iamGroupAdminPolicy) Check(r ir.Resource) []ir.Finding {
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil
	}
	if policyHasWildcardAdmin(doc) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-555",
			Title:       (iamGroupAdminPolicy{}).Title(),
			Description: (iamGroupAdminPolicy{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "Action * on Resource *",
				Expected:  "scoped actions and resources",
			},
		}}
	}
	return nil
}

// policyHasWildcardAdmin reports whether a policy JSON document contains an
// Allow statement with Action "*" on Resource "*".
func policyHasWildcardAdmin(doc string) bool {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return false
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
		if !policyValueHas(m["Action"], "*") {
			continue
		}
		if !policyValueHas(m["Resource"], "*") {
			continue
		}
		return true
	}
	return false
}

// policyValueHas reports whether v (string or list) contains target
// (case-insensitive, trimmed).
func policyValueHas(v any, target string) bool {
	switch t := v.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(t), target)
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && strings.EqualFold(strings.TrimSpace(s), target) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-556: Transit Gateway route table with default propagation
// ---------------------------------------------------------------------------

type tgwPermissivePropagation struct{}

func (tgwPermissivePropagation) ID() string { return "AEGIS-AWS-556" }
func (tgwPermissivePropagation) Title() string {
	return "Transit Gateway route table propagation enabled"
}
func (tgwPermissivePropagation) Description() string {
	return "Transit Gateway route table propagation automatically spreads " +
		"routes from attachments, which can unintentionally expose VPCs to " +
		"each other. Review each aws_ec2_transit_gateway_route_table_propagation " +
		"and disable it where cross-VPC routing is not required."
}
func (tgwPermissivePropagation) Severity() ir.Severity { return ir.SeverityHigh }
func (tgwPermissivePropagation) AppliesTo(resType string) bool {
	return resType == "aws_ec2_transit_gateway_route_table_propagation"
}
func (tgwPermissivePropagation) Check(r ir.Resource) []ir.Finding {
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-556",
		Title:       (tgwPermissivePropagation{}).Title(),
		Description: (tgwPermissivePropagation{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "transit_gateway_route_table_id",
			Span:      evidenceSpan(ir.Span{}, r.Span),
			Actual:    "propagation enabled",
			Expected:  "propagation disabled unless explicitly required",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-557: VPC endpoint policy allows all principals
// ---------------------------------------------------------------------------

type vpcEndpointOpenPolicy struct{}

func (vpcEndpointOpenPolicy) ID() string { return "AEGIS-AWS-557" }
func (vpcEndpointOpenPolicy) Title() string {
	return "VPC endpoint policy allows all principals"
}
func (vpcEndpointOpenPolicy) Description() string {
	return "VPC endpoint policies with \"Principal\": \"*\" allow any AWS " +
		"principal to use the endpoint, defeating the purpose of private " +
		"connectivity. Scope the Principal to specific accounts or roles."
}
func (vpcEndpointOpenPolicy) Severity() ir.Severity { return ir.SeverityMedium }
func (vpcEndpointOpenPolicy) AppliesTo(resType string) bool {
	return resType == "aws_vpc_endpoint"
}
func (vpcEndpointOpenPolicy) Check(r ir.Resource) []ir.Finding {
	doc, span, present, known := getString(r, "policy")
	if !present {
		// Optional; without a policy the default endpoint policy applies,
		// which allows full access: any principal can use the endpoint.
		return absentInsecureDefault(vpcEndpointOpenPolicy{}, r,
			"policy", "absent (default policy allows full access)",
			"scoped Principal (account IDs or ARNs)")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if policyHasWildcardPrincipal(doc) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-557",
			Title:       (vpcEndpointOpenPolicy{}).Title(),
			Description: (vpcEndpointOpenPolicy{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "Principal *",
				Expected:  "scoped Principal (account IDs or ARNs)",
			},
		}}
	}
	return nil
}

// policyHasWildcardPrincipal reports whether a policy JSON document contains
// a statement with Principal "*".
func policyHasWildcardPrincipal(doc string) bool {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return false
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
		if policyValueHas(m["Principal"], "*") {
			return true
		}
		// Principal can also be {"AWS": "*"}.
		if pm, ok := m["Principal"].(map[string]any); ok {
			for _, v := range pm {
				if policyValueHas(v, "*") {
					return true
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-560: S3 bucket with force_destroy enabled
// ---------------------------------------------------------------------------

type s3ForceDestroy struct{}

func (s3ForceDestroy) ID() string { return "AEGIS-AWS-560" }
func (s3ForceDestroy) Title() string {
	return "S3 bucket with force_destroy enabled"
}
func (s3ForceDestroy) Description() string {
	return "Hygiene: force_destroy = true allows Terraform to delete a " +
		"bucket even when it contains objects, risking data loss. Remove " +
		"force_destroy or set it to false for production buckets."
}
func (s3ForceDestroy) Severity() ir.Severity { return ir.SeverityLow }
func (s3ForceDestroy) AppliesTo(resType string) bool {
	return resType == "aws_s3_bucket"
}
func (s3ForceDestroy) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "force_destroy")
	if present && !known {
		return nil
	}
	if present && val {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-560",
			(s3ForceDestroy{}).Title(), (s3ForceDestroy{}).Description(),
			r, "force_destroy", span, "true",
			"force_destroy = false or removed")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-561: KMS key with short deletion window
// ---------------------------------------------------------------------------

type kmsShortDeletionWindow struct{}

func (kmsShortDeletionWindow) ID() string { return "AEGIS-AWS-561" }
func (kmsShortDeletionWindow) Title() string {
	return "KMS key with deletion window under 7 days"
}
func (kmsShortDeletionWindow) Description() string {
	return "KMS keys should use a deletion window of at least 7 days " +
		"(AWS minimum) so accidental deletion can be cancelled. Longer " +
		"windows (30 days) are recommended. Set deletion_window_in_days >= 7."
}
func (kmsShortDeletionWindow) Severity() ir.Severity { return ir.SeverityHigh }
func (kmsShortDeletionWindow) AppliesTo(resType string) bool {
	return resType == "aws_kms_key"
}
func (kmsShortDeletionWindow) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getNumber(r, "deletion_window_in_days")
	if !present || !known {
		return nil
	}
	if val < 7 {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-561",
			Title:       (kmsShortDeletionWindow{}).Title(),
			Description: (kmsShortDeletionWindow{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "deletion_window_in_days",
				Span:      evidenceSpan(span, r.Span),
				Actual:    strconv.FormatFloat(val, 'f', -1, 64),
				Expected:  "deletion_window_in_days >= 7",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-562: KMS grant with wildcard operations
// ---------------------------------------------------------------------------

type kmsGrantWildcard struct{}

func (kmsGrantWildcard) ID() string { return "AEGIS-AWS-562" }
func (kmsGrantWildcard) Title() string {
	return "KMS grant with wildcard operations"
}
func (kmsGrantWildcard) Description() string {
	return "KMS grants should list only the specific operations the " +
		"grantee needs. Wildcard operations delegate full key control. " +
		"Replace \"*\" with the minimal operation set."
}
func (kmsGrantWildcard) Severity() ir.Severity { return ir.SeverityMedium }
func (kmsGrantWildcard) AppliesTo(resType string) bool {
	return resType == "aws_kms_grant"
}
func (kmsGrantWildcard) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["operations"]
	if !ok {
		return nil
	}
	if !v.Known {
		return nil
	}
	l, ok := v.AsList()
	if !ok {
		return nil
	}
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			continue
		}
		if strings.TrimSpace(s) == "*" {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-562",
				Title:       (kmsGrantWildcard{}).Title(),
				Description: (kmsGrantWildcard{}).Description(),
				Severity:    ir.SeverityMedium,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "operations",
					Span:      evidenceSpan(v.Span, r.Span),
					Actual:    "contains *",
					Expected:  "explicit minimal operation list",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-563: Secrets Manager secret without customer-managed key
// ---------------------------------------------------------------------------

type secretsNoCMK struct{}

func (secretsNoCMK) ID() string { return "AEGIS-AWS-563" }
func (secretsNoCMK) Title() string {
	return "Secrets Manager secret without customer-managed KMS key"
}
func (secretsNoCMK) Description() string {
	return "Secrets Manager secrets should use a customer-managed KMS key " +
		"(kms_key_id) instead of the default AWS-managed key, so key " +
		"rotation and access policies are under your control. Set kms_key_id."
}
func (secretsNoCMK) Severity() ir.Severity { return ir.SeverityMedium }
func (secretsNoCMK) AppliesTo(resType string) bool {
	return resType == "aws_secretsmanager_secret"
}
func (secretsNoCMK) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "kms_key_id")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-563",
			Title:       (secretsNoCMK{}).Title(),
			Description: (secretsNoCMK{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "kms_key_id",
				Span:      evidenceSpan(ir.Span{}, r.Span),
				Actual:    "absent (AWS-managed key)",
				Expected:  "kms_key_id set to a customer-managed key",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-564: Lambda with explicitly unlimited concurrency
// ---------------------------------------------------------------------------

type lambdaUnlimitedConcurrency struct{}

func (lambdaUnlimitedConcurrency) ID() string { return "AEGIS-AWS-564" }
func (lambdaUnlimitedConcurrency) Title() string {
	return "Lambda function with explicitly unlimited concurrency"
}
func (lambdaUnlimitedConcurrency) Description() string {
	return "Setting reserved_concurrent_executions = -1 explicitly opts out " +
		"of concurrency limits, allowing unbounded scaling and runaway " +
		"cost. (Absent values are covered by AEGIS-AWS-548 hygiene.) Set an " +
		"explicit positive limit."
}
func (lambdaUnlimitedConcurrency) Severity() ir.Severity { return ir.SeverityMedium }
func (lambdaUnlimitedConcurrency) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}
func (lambdaUnlimitedConcurrency) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getNumber(r, "reserved_concurrent_executions")
	if !present || !known {
		return nil // absent is AEGIS-AWS-548; unresolved: cannot decide
	}
	if val == -1 {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-564",
			Title:       (lambdaUnlimitedConcurrency{}).Title(),
			Description: (lambdaUnlimitedConcurrency{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "reserved_concurrent_executions",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "-1",
				Expected:  "explicit positive concurrency limit",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-565: EC2 instance with EBS optimization disabled (hygiene)
// ---------------------------------------------------------------------------

type ec2NoEBSOptimized struct{}

func (ec2NoEBSOptimized) ID() string { return "AEGIS-AWS-565" }
func (ec2NoEBSOptimized) Title() string {
	return "EC2 instance with EBS optimization explicitly disabled"
}
func (ec2NoEBSOptimized) Description() string {
	return "Hygiene: EC2 instances should enable EBS optimization for " +
		"dedicated EBS throughput. Only flags explicitly disabled " +
		"(ebs_optimized = false); unset values follow instance-type defaults."
}
func (ec2NoEBSOptimized) Severity() ir.Severity { return ir.SeverityLow }
func (ec2NoEBSOptimized) AppliesTo(resType string) bool {
	return resType == "aws_instance"
}
func (ec2NoEBSOptimized) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "ebs_optimized")
	if present && !known {
		return nil
	}
	if present && !val {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-565",
			(ec2NoEBSOptimized{}).Title(), (ec2NoEBSOptimized{}).Description(),
			r, "ebs_optimized", span, "false",
			"ebs_optimized = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-566: RDS Performance Insights without CMK
// ---------------------------------------------------------------------------

type rdsPerfInsightsNoCMK struct{}

func (rdsPerfInsightsNoCMK) ID() string { return "AEGIS-AWS-566" }
func (rdsPerfInsightsNoCMK) Title() string {
	return "RDS Performance Insights without customer-managed KMS key"
}
func (rdsPerfInsightsNoCMK) Description() string {
	return "When Performance Insights is enabled, its data should be " +
		"encrypted with a customer-managed KMS key rather than the default " +
		"AWS key. Set performance_insights_kms_key_id."
}
func (rdsPerfInsightsNoCMK) Severity() ir.Severity { return ir.SeverityMedium }
func (rdsPerfInsightsNoCMK) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}
func (rdsPerfInsightsNoCMK) Check(r ir.Resource) []ir.Finding {
	enabled, _, epresent, eknown := getBool(r, "performance_insights_enabled")
	if !epresent || !eknown || !enabled {
		return nil
	}
	_, _, kpresent, kknown := getString(r, "performance_insights_kms_key_id")
	if kpresent && !kknown {
		return nil
	}
	if !kpresent {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-566",
			Title:       (rdsPerfInsightsNoCMK{}).Title(),
			Description: (rdsPerfInsightsNoCMK{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "performance_insights_kms_key_id",
				Span:      evidenceSpan(ir.Span{}, r.Span),
				Actual:    "absent (AWS-managed key)",
				Expected:  "performance_insights_kms_key_id set",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-567: Security Hub not enabled (module-level)
// ---------------------------------------------------------------------------

type noSecurityHub struct{}

func (noSecurityHub) ID() string { return "AEGIS-AWS-567" }
func (noSecurityHub) Title() string {
	return "Security Hub not enabled in module"
}
func (noSecurityHub) Description() string {
	return "AWS Security Hub should be enabled for centralized security " +
		"findings aggregation and CIS benchmark checks. Add an " +
		"aws_securityhub_account resource. Only evaluated on modules with " +
		"15+ resources to avoid noise on trivial configurations."
}
func (noSecurityHub) Severity() ir.Severity { return ir.SeverityLow }
func (noSecurityHub) AppliesTo(resType string) bool {
	return resType == "aws_securityhub_account"
}
func (noSecurityHub) Check(ir.Resource) []ir.Finding { return nil }
func (noSecurityHub) CheckAll(resources []ir.Resource) []ir.Finding {
	if len(resources) < 15 {
		return nil // trivial module: skip to avoid noise
	}
	for _, r := range resources {
		if r.Type == "aws_securityhub_account" {
			return nil
		}
	}
	// Emit one finding anchored on the first resource's span.
	anchor := resources[0]
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-567",
		Title:       (noSecurityHub{}).Title(),
		Description: (noSecurityHub{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    "module",
		Evidence: ir.Evidence{
			Attribute: "aws_securityhub_account",
			Span:      evidenceSpan(ir.Span{}, anchor.Span),
			Actual:    "absent",
			Expected:  "aws_securityhub_account resource present",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-568: CloudTrail without KMS encryption
// ---------------------------------------------------------------------------

type cloudtrailNoKMS struct{}

func (cloudtrailNoKMS) ID() string { return "AEGIS-AWS-568" }
func (cloudtrailNoKMS) Title() string {
	return "CloudTrail trail without KMS encryption"
}
func (cloudtrailNoKMS) Description() string {
	return "CloudTrail log files should be encrypted with a customer-managed " +
		"KMS key so log integrity is under your control. Set kms_key_id on " +
		"the aws_cloudtrail resource."
}
func (cloudtrailNoKMS) Severity() ir.Severity { return ir.SeverityMedium }
func (cloudtrailNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_cloudtrail"
}
func (cloudtrailNoKMS) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "kms_key_id")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-568",
			Title:       (cloudtrailNoKMS{}).Title(),
			Description: (cloudtrailNoKMS{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "kms_key_id",
				Span:      evidenceSpan(ir.Span{}, r.Span),
				Actual:    "absent",
				Expected:  "kms_key_id set to a customer-managed key",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-569: Detective not enabled (module-level)
// ---------------------------------------------------------------------------

type noDetective struct{}

func (noDetective) ID() string { return "AEGIS-AWS-569" }
func (noDetective) Title() string {
	return "Amazon Detective not enabled in module"
}
func (noDetective) Description() string {
	return "Amazon Detective should be enabled for ML-driven security " +
		"investigation across CloudTrail, VPC flow logs, and GuardDuty " +
		"findings. Add an aws_detective_graph resource. Only evaluated on " +
		"modules with 15+ resources to avoid noise on trivial configurations."
}
func (noDetective) Severity() ir.Severity { return ir.SeverityLow }
func (noDetective) AppliesTo(resType string) bool {
	return resType == "aws_detective_graph"
}
func (noDetective) Check(ir.Resource) []ir.Finding { return nil }
func (noDetective) CheckAll(resources []ir.Resource) []ir.Finding {
	if len(resources) < 15 {
		return nil
	}
	for _, r := range resources {
		if r.Type == "aws_detective_graph" {
			return nil
		}
	}
	anchor := resources[0]
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-569",
		Title:       (noDetective{}).Title(),
		Description: (noDetective{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    "module",
		Evidence: ir.Evidence{
			Attribute: "aws_detective_graph",
			Span:      evidenceSpan(ir.Span{}, anchor.Span),
			Actual:    "absent",
			Expected:  "aws_detective_graph resource present",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-570: CloudTrail S3 bucket without MFA delete (hygiene)
// ---------------------------------------------------------------------------

type trailBucketNoMFADelete struct{}

func (trailBucketNoMFADelete) ID() string { return "AEGIS-AWS-570" }
func (trailBucketNoMFADelete) Title() string {
	return "CloudTrail S3 bucket without MFA delete protection"
}
func (trailBucketNoMFADelete) Description() string {
	return "Hygiene: S3 buckets storing CloudTrail logs should enable MFA " +
		"delete on versioning so log tampering requires MFA. Set mfa_delete " +
		"= \"Enabled\" in the aws_s3_bucket_versioning configuration."
}
func (trailBucketNoMFADelete) Severity() ir.Severity { return ir.SeverityLow }
func (trailBucketNoMFADelete) AppliesTo(resType string) bool {
	return resType == "aws_cloudtrail"
}
func (trailBucketNoMFADelete) Check(ir.Resource) []ir.Finding { return nil }
func (trailBucketNoMFADelete) CheckAll(resources []ir.Resource) []ir.Finding {
	// Index versioning configs by target bucket (directory-scoped) address.
	mfaDelete := map[string]bool{}
	for _, r := range resources {
		if r.Type != "aws_s3_bucket_versioning" {
			continue
		}
		addr, ok := linkedBucketAddr(r, resources)
		if !ok {
			continue
		}
		blks, _, present, known := getBlocks(r, "versioning_configuration")
		if !present || !known {
			continue
		}
		for _, b := range blks {
			mfa, _, mpresent, mknown := blockString(b, "mfa_delete")
			if mpresent && mknown && strings.EqualFold(strings.TrimSpace(mfa), "Enabled") {
				mfaDelete[addr] = true
			}
		}
	}
	var out []ir.Finding
	for _, t := range resources {
		if t.Type != "aws_cloudtrail" {
			continue
		}
		bktAddr := trailBucketAddr(t, resources)
		if bktAddr == "" {
			continue // cannot resolve: never flag
		}
		if mfaDelete[bktAddr] {
			continue
		}
		bkt := ir.Resource{}
		for _, b := range resources {
			if b.Type == "aws_s3_bucket" && scopeKey(b) == bktAddr {
				bkt = b
				break
			}
		}
		out = append(out, hygieneFinding("AEGIS-AWS-570",
			(trailBucketNoMFADelete{}).Title(), (trailBucketNoMFADelete{}).Description(),
			bkt, "mfa_delete", bkt.Span, "not enabled",
			"mfa_delete = \"Enabled\" on CloudTrail log bucket"))
	}
	return out
}

// trailBucketAddr resolves an aws_cloudtrail's s3_bucket_name to the bucket's
// scoped address, via reference or name lookup. Directory-scoped: only buckets
// from the trail's own source directory are candidates, so same-named buckets
// in different scanned projects never cross-contaminate.
func trailBucketAddr(t ir.Resource, resources []ir.Resource) string {
	v, ok := t.Attributes["s3_bucket_name"]
	if !ok || !v.Known {
		return ""
	}
	if v.IsRef() {
		if addr, ok := refAddrOf(v.Ref); ok {
			for _, b := range resources {
				if b.Type == "aws_s3_bucket" && b.Address() == addr && sameScope(t, b) {
					return scopeKey(b)
				}
			}
		}
		return ""
	}
	name, ok := v.AsString()
	if !ok {
		return ""
	}
	name = strings.TrimSpace(name)
	for _, b := range resources {
		if b.Type != "aws_s3_bucket" || !sameScope(t, b) {
			continue
		}
		if b.Name == name {
			return scopeKey(b)
		}
		if bn, _, _, known := getString(b, "bucket"); known && strings.TrimSpace(bn) == name {
			return scopeKey(b)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-571: CodeArtifact repository without upstream restrictions
// ---------------------------------------------------------------------------

type codeartifactNoUpstream struct{}

func (codeartifactNoUpstream) ID() string { return "AEGIS-AWS-571" }
func (codeartifactNoUpstream) Title() string {
	return "CodeArtifact repository without upstream configuration"
}
func (codeartifactNoUpstream) Description() string {
	return "CodeArtifact repositories should declare upstream repositories " +
		"explicitly so package provenance is controlled. A repository " +
		"without an upstream block may pull from unexpected external " +
		"sources. Add an upstream block."
}
func (codeartifactNoUpstream) Severity() ir.Severity { return ir.SeverityMedium }
func (codeartifactNoUpstream) AppliesTo(resType string) bool {
	return resType == "aws_codeartifact_repository"
}
func (codeartifactNoUpstream) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "upstream")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-571",
			Title:       (codeartifactNoUpstream{}).Title(),
			Description: (codeartifactNoUpstream{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "upstream",
				Span:      evidenceSpan(ir.Span{}, r.Span),
				Actual:    "absent",
				Expected:  "upstream block with repository_name",
			},
		}}
	}
	return nil
}

// CoverageGapRules returns the coverage-gap rules in ID order (552–571).
func CoverageGapRules() []ir.Rule {
	return []ir.Rule{
		iamAccessKeyNoPGP{},          // AEGIS-AWS-552
		iamPolicyNotActionAllow{},    // AEGIS-AWS-553
		iamRoleLongSession{},         // AEGIS-AWS-554
		iamGroupAdminPolicy{},        // AEGIS-AWS-555
		tgwPermissivePropagation{},   // AEGIS-AWS-556
		vpcEndpointOpenPolicy{},      // AEGIS-AWS-557
		s3ForceDestroy{},             // AEGIS-AWS-560
		kmsShortDeletionWindow{},     // AEGIS-AWS-561
		kmsGrantWildcard{},           // AEGIS-AWS-562
		secretsNoCMK{},               // AEGIS-AWS-563
		lambdaUnlimitedConcurrency{}, // AEGIS-AWS-564
		ec2NoEBSOptimized{},          // AEGIS-AWS-565
		rdsPerfInsightsNoCMK{},       // AEGIS-AWS-566
		noSecurityHub{},              // AEGIS-AWS-567
		cloudtrailNoKMS{},            // AEGIS-AWS-568
		noDetective{},                // AEGIS-AWS-569
		trailBucketNoMFADelete{},     // AEGIS-AWS-570
		codeartifactNoUpstream{},     // AEGIS-AWS-571
	}
}
