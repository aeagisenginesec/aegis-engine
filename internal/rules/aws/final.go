package aws

import (
	"strings"

	"aegis/internal/ir"
)

// FinalRules returns the last AWS sweep (AEGIS-AWS-431–442), in ID order.
func FinalRules() []ir.Rule {
	return []ir.Rule{
		redshiftServerlessPublic{},  // AEGIS-AWS-431
		redshiftServerlessNoKMS{},   // AEGIS-AWS-432
		vpcEndpointPublicPolicy{},   // AEGIS-AWS-433
		glueJobNoSecConfig{},        // AEGIS-AWS-434
		timestreamNoKMS{},           // AEGIS-AWS-435
		rdsProxyNoTLS{},             // AEGIS-AWS-436
		appstreamDefaultInternet{},  // AEGIS-AWS-437
		netFirewallNoDelProtect{},   // AEGIS-AWS-438
		memorydbNoSnapshots{},       // AEGIS-AWS-439
		neptuneNoDelProtect{},       // AEGIS-AWS-440
		s3AccessPointPublicPolicy{}, // AEGIS-AWS-441
		vpcEndpointSvcNoAccept{},    // AEGIS-AWS-442
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-431: Redshift Serverless workgroup publicly accessible
// ---------------------------------------------------------------------------

type redshiftServerlessPublic struct{}

func (redshiftServerlessPublic) ID() string { return "AEGIS-AWS-431" }
func (redshiftServerlessPublic) Title() string {
	return "Redshift Serverless workgroup publicly accessible"
}
func (redshiftServerlessPublic) Description() string {
	return "A publicly accessible Redshift Serverless workgroup exposes the " +
		"data warehouse endpoint to the internet."
}
func (redshiftServerlessPublic) Severity() ir.Severity { return ir.SeverityHigh }
func (redshiftServerlessPublic) AppliesTo(resType string) bool {
	return resType == "aws_redshiftserverless_workgroup"
}

func (redshiftServerlessPublic) Check(r ir.Resource) []ir.Finding {
	pub, span, present, known := getBool(r, "publicly_accessible")
	if !present || !known || !pub {
		return nil // absent/false/unresolved: no public flag, no finding
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-431",
		Title:       (redshiftServerlessPublic{}).Title(),
		Description: (redshiftServerlessPublic{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "publicly_accessible",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-432: Redshift Serverless namespace without KMS
// ---------------------------------------------------------------------------

type redshiftServerlessNoKMS struct{}

func (redshiftServerlessNoKMS) ID() string { return "AEGIS-AWS-432" }
func (redshiftServerlessNoKMS) Title() string {
	return "Redshift Serverless namespace without customer-managed KMS key"
}
func (redshiftServerlessNoKMS) Description() string {
	return "Without kms_key_id the namespace uses the AWS-owned key; a " +
		"customer-managed key is required for full control over encryption."
}
func (redshiftServerlessNoKMS) Severity() ir.Severity { return ir.SeverityMedium }
func (redshiftServerlessNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_redshiftserverless_namespace"
}

func (redshiftServerlessNoKMS) Check(r ir.Resource) []ir.Finding {
	key, span, present, known := getString(r, "kms_key_id")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(key) != "" {
		return nil
	}
	actual := "absent (AWS-owned key)"
	if present {
		actual = "empty"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-432",
		Title:       (redshiftServerlessNoKMS{}).Title(),
		Description: (redshiftServerlessNoKMS{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "kms_key_id",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "customer-managed KMS key ARN",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-433: VPC endpoint policy public
// ---------------------------------------------------------------------------

type vpcEndpointPublicPolicy struct{}

func (vpcEndpointPublicPolicy) ID() string { return "AEGIS-AWS-433" }
func (vpcEndpointPublicPolicy) Title() string {
	return "VPC endpoint with public policy"
}
func (vpcEndpointPublicPolicy) Description() string {
	return "An absent policy means AWS applies the default endpoint policy, " +
		"which allows full access to the service. An explicit policy granting " +
		"a public principal has the same effect."
}
func (vpcEndpointPublicPolicy) Severity() ir.Severity { return ir.SeverityHigh }
func (vpcEndpointPublicPolicy) AppliesTo(resType string) bool {
	return resType == "aws_vpc_endpoint"
}

func (vpcEndpointPublicPolicy) Check(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "policy")
	if !present {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-433",
			Title:       (vpcEndpointPublicPolicy{}).Title(),
			Description: (vpcEndpointPublicPolicy{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent (AWS default: full access)",
				Expected:  "restrictive endpoint policy",
			},
		}}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if !policyAllowsPublicPrincipal(pol) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-433",
		Title:       (vpcEndpointPublicPolicy{}).Title(),
		Description: (vpcEndpointPublicPolicy{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "policy",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "policy allows public principal",
			Expected:  "restrictive endpoint policy",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-434: Glue job without security configuration
// ---------------------------------------------------------------------------

type glueJobNoSecConfig struct{}

func (glueJobNoSecConfig) ID() string { return "AEGIS-AWS-434" }
func (glueJobNoSecConfig) Title() string {
	return "Glue job without security configuration"
}
func (glueJobNoSecConfig) Description() string {
	return "Without a security configuration the job lacks encryption for " +
		"job bookmarks, CloudWatch logs, and S3 data."
}
func (glueJobNoSecConfig) Severity() ir.Severity { return ir.SeverityMedium }
func (glueJobNoSecConfig) AppliesTo(resType string) bool {
	return resType == "aws_glue_job"
}

func (glueJobNoSecConfig) Check(r ir.Resource) []ir.Finding {
	cfg, span, present, known := getString(r, "security_configuration")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(cfg) != "" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-434",
		Title:       (glueJobNoSecConfig{}).Title(),
		Description: (glueJobNoSecConfig{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "security_configuration",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "absent",
			Expected:  "security_configuration referencing an aws_glue_security_configuration",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-435: Timestream database without KMS
// ---------------------------------------------------------------------------

type timestreamNoKMS struct{}

func (timestreamNoKMS) ID() string { return "AEGIS-AWS-435" }
func (timestreamNoKMS) Title() string {
	return "Timestream database without customer-managed KMS key"
}
func (timestreamNoKMS) Description() string {
	return "Without kms_key_id the database uses the AWS-owned key; a " +
		"customer-managed key is required for full control over encryption."
}
func (timestreamNoKMS) Severity() ir.Severity { return ir.SeverityMedium }
func (timestreamNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_timestreamwrite_database"
}

func (timestreamNoKMS) Check(r ir.Resource) []ir.Finding {
	key, span, present, known := getString(r, "kms_key_id")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(key) != "" {
		return nil
	}
	actual := "absent (AWS-owned key)"
	if present {
		actual = "empty"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-435",
		Title:       (timestreamNoKMS{}).Title(),
		Description: (timestreamNoKMS{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "kms_key_id",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "customer-managed KMS key ID",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-436: RDS proxy without TLS
// ---------------------------------------------------------------------------

type rdsProxyNoTLS struct{}

func (rdsProxyNoTLS) ID() string { return "AEGIS-AWS-436" }
func (rdsProxyNoTLS) Title() string {
	return "RDS proxy without TLS enforcement"
}
func (rdsProxyNoTLS) Description() string {
	return "Without require_tls, clients may connect to the RDS proxy over " +
		"plaintext, exposing credentials and queries on the network."
}
func (rdsProxyNoTLS) Severity() ir.Severity { return ir.SeverityHigh }
func (rdsProxyNoTLS) AppliesTo(resType string) bool {
	return resType == "aws_db_proxy"
}

func (rdsProxyNoTLS) Check(r ir.Resource) []ir.Finding {
	tls, span, present, known := getBool(r, "require_tls")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && tls {
		return nil
	}
	actual := "absent (provider default: TLS not enforced)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-436",
		Title:       (rdsProxyNoTLS{}).Title(),
		Description: (rdsProxyNoTLS{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "require_tls",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-437: AppStream fleet with default internet access
// ---------------------------------------------------------------------------

type appstreamDefaultInternet struct{}

func (appstreamDefaultInternet) ID() string { return "AEGIS-AWS-437" }
func (appstreamDefaultInternet) Title() string {
	return "AppStream fleet with default internet access"
}
func (appstreamDefaultInternet) Description() string {
	return "enable_default_internet_access gives streaming instances a public " +
		"route to the internet, bypassing VPC egress controls."
}
func (appstreamDefaultInternet) Severity() ir.Severity { return ir.SeverityMedium }
func (appstreamDefaultInternet) AppliesTo(resType string) bool {
	return resType == "aws_appstream_fleet"
}

func (appstreamDefaultInternet) Check(r ir.Resource) []ir.Finding {
	open, span, present, known := getBool(r, "enable_default_internet_access")
	if !present || !known || !open {
		return nil // absent/false/unresolved: no finding
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-437",
		Title:       (appstreamDefaultInternet{}).Title(),
		Description: (appstreamDefaultInternet{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "enable_default_internet_access",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false (route egress through the VPC)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-438: Network Firewall without delete protection
// ---------------------------------------------------------------------------

type netFirewallNoDelProtect struct{}

func (netFirewallNoDelProtect) ID() string { return "AEGIS-AWS-438" }
func (netFirewallNoDelProtect) Title() string {
	return "Network Firewall without delete protection"
}
func (netFirewallNoDelProtect) Description() string {
	return "Without delete protection the firewall can be removed by any " +
		"principal with delete permissions, silently dropping inspection."
}
func (netFirewallNoDelProtect) Severity() ir.Severity { return ir.SeverityMedium }
func (netFirewallNoDelProtect) AppliesTo(resType string) bool {
	return resType == "aws_networkfirewall_firewall"
}

func (netFirewallNoDelProtect) Check(r ir.Resource) []ir.Finding {
	prot, span, present, known := getBool(r, "delete_protection")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && prot {
		return nil
	}
	actual := "absent (provider default: disabled)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-438",
		Title:       (netFirewallNoDelProtect{}).Title(),
		Description: (netFirewallNoDelProtect{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "delete_protection",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-439: MemoryDB cluster without snapshot retention
// ---------------------------------------------------------------------------

type memorydbNoSnapshots struct{}

func (memorydbNoSnapshots) ID() string { return "AEGIS-AWS-439" }
func (memorydbNoSnapshots) Title() string {
	return "MemoryDB cluster without snapshot retention"
}
func (memorydbNoSnapshots) Description() string {
	return "Without snapshot_retention_limit the cluster keeps no automated " +
		"snapshots, leaving no recovery point after data loss."
}
func (memorydbNoSnapshots) Severity() ir.Severity { return ir.SeverityMedium }
func (memorydbNoSnapshots) AppliesTo(resType string) bool {
	return resType == "aws_memorydb_cluster"
}

func (memorydbNoSnapshots) Check(r ir.Resource) []ir.Finding {
	n, span, present, known := getNumber(r, "snapshot_retention_limit")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && n > 0 {
		return nil
	}
	actual := "absent (provider default: 0)"
	if present {
		actual = "0"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-439",
		Title:       (memorydbNoSnapshots{}).Title(),
		Description: (memorydbNoSnapshots{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "snapshot_retention_limit",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "> 0 days",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-440: Neptune cluster without deletion protection
// ---------------------------------------------------------------------------

type neptuneNoDelProtect struct{}

func (neptuneNoDelProtect) ID() string { return "AEGIS-AWS-440" }
func (neptuneNoDelProtect) Title() string {
	return "Neptune cluster without deletion protection"
}
func (neptuneNoDelProtect) Description() string {
	return "Without deletion_protection the graph database cluster can be " +
		"deleted by any principal with delete permissions."
}
func (neptuneNoDelProtect) Severity() ir.Severity { return ir.SeverityMedium }
func (neptuneNoDelProtect) AppliesTo(resType string) bool {
	return resType == "aws_neptune_cluster"
}

func (neptuneNoDelProtect) Check(r ir.Resource) []ir.Finding {
	prot, span, present, known := getBool(r, "deletion_protection")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && prot {
		return nil
	}
	actual := "absent (provider default: disabled)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-440",
		Title:       (neptuneNoDelProtect{}).Title(),
		Description: (neptuneNoDelProtect{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "deletion_protection",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-441: S3 access point policy public
// ---------------------------------------------------------------------------

type s3AccessPointPublicPolicy struct{}

func (s3AccessPointPublicPolicy) ID() string { return "AEGIS-AWS-441" }
func (s3AccessPointPublicPolicy) Title() string {
	return "S3 access point policy allows public principal"
}
func (s3AccessPointPublicPolicy) Description() string {
	return "An Allow statement with Principal \"*\" on an S3 access point " +
		"policy grants anonymous access through the access point."
}
func (s3AccessPointPublicPolicy) Severity() ir.Severity { return ir.SeverityHigh }
func (s3AccessPointPublicPolicy) AppliesTo(resType string) bool {
	return resType == "aws_s3control_access_point_policy"
}

func (s3AccessPointPublicPolicy) Check(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent/unresolved: nothing to judge
	}
	if !policyAllowsPublicPrincipal(pol) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-441",
		Title:       (s3AccessPointPublicPolicy{}).Title(),
		Description: (s3AccessPointPublicPolicy{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "policy",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "policy allows public principal",
			Expected:  "restricted principals only",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-442: VPC endpoint service without acceptance required
// ---------------------------------------------------------------------------

type vpcEndpointSvcNoAccept struct{}

func (vpcEndpointSvcNoAccept) ID() string { return "AEGIS-AWS-442" }
func (vpcEndpointSvcNoAccept) Title() string {
	return "VPC endpoint service without acceptance required"
}
func (vpcEndpointSvcNoAccept) Description() string {
	return "Without acceptance_required, any principal can create an endpoint " +
		"against this service with no approval step."
}
func (vpcEndpointSvcNoAccept) Severity() ir.Severity { return ir.SeverityMedium }
func (vpcEndpointSvcNoAccept) AppliesTo(resType string) bool {
	return resType == "aws_vpc_endpoint_service"
}

func (vpcEndpointSvcNoAccept) Check(r ir.Resource) []ir.Finding {
	req, span, present, known := getBool(r, "acceptance_required")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && req {
		return nil
	}
	actual := "absent (provider default: disabled)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-442",
		Title:       (vpcEndpointSvcNoAccept{}).Title(),
		Description: (vpcEndpointSvcNoAccept{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "acceptance_required",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "true",
		},
	}}
}
