package aws

import (
	"encoding/json"
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// ComputeRules returns the AEGIS-AWS-301..310 compute-service rules in ID
// order. Wired into the pack by the parent; this file owns the 301-310 range.
func ComputeRules() []ir.Rule {
	return []ir.Rule{
		launchTemplateUnencryptedEBS{},
		ecsPrivilegedContainer{},
		ecrNoImageScanning{},
		eksNoSecretsEncryption{},
		eksPublicEndpoint{},
		eksNoControlPlaneLogging{},
		lambdaEnvNoKMS{},
		lambdaNoActiveTracing{},
		launchConfigurationDeprecated{},
		ec2NoDetailedMonitoring{},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-301: Launch template EBS volumes unencrypted
// ---------------------------------------------------------------------------

type launchTemplateUnencryptedEBS struct{}

func (launchTemplateUnencryptedEBS) ID() string { return "AEGIS-AWS-301" }
func (launchTemplateUnencryptedEBS) Title() string {
	return "Launch template EBS volumes unencrypted"
}
func (launchTemplateUnencryptedEBS) Description() string {
	return "A block_device_mappings entry in an aws_launch_template whose ebs " +
		"map has encrypted = false leaves the volume readable at rest. " +
		"(Known false only; absent follows the provider default.)"
}
func (launchTemplateUnencryptedEBS) Severity() ir.Severity { return ir.SeverityHigh }

func (launchTemplateUnencryptedEBS) AppliesTo(resType string) bool {
	return resType == "aws_launch_template"
}

func (launchTemplateUnencryptedEBS) Check(r ir.Resource) []ir.Finding {
	mappings, _, present, known := getBlocks(r, "block_device_mappings")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	mk := func(span ir.Span, actual string) []ir.Finding {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-301",
			Title:       (launchTemplateUnencryptedEBS{}).Title(),
			Description: (launchTemplateUnencryptedEBS{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "block_device_mappings.ebs.encrypted",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "encrypted = true",
			},
		}}
	}
	for _, m := range mappings {
		for _, ebs := range blockList(m, "ebs") {
			enc, espan, epresent, eknown := blockBool(ebs, "encrypted")
			if !epresent {
				continue // provider default: not proven insecure
			}
			if !eknown {
				return nil // unresolved: cannot decide
			}
			if !enc {
				return mk(espan, "false")
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-302: ECS task definition with privileged container
// ---------------------------------------------------------------------------

type ecsPrivilegedContainer struct{}

func (ecsPrivilegedContainer) ID() string { return "AEGIS-AWS-302" }
func (ecsPrivilegedContainer) Title() string {
	return "ECS task definition with privileged container"
}
func (ecsPrivilegedContainer) Description() string {
	return "A container with privileged = true in container_definitions runs " +
		"with all host capabilities, escaping container isolation."
}
func (ecsPrivilegedContainer) Severity() ir.Severity { return ir.SeverityHigh }

func (ecsPrivilegedContainer) AppliesTo(resType string) bool {
	return resType == "aws_ecs_task_definition"
}

func (ecsPrivilegedContainer) Check(r ir.Resource) []ir.Finding {
	raw, span, present, known := getString(r, "container_definitions")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	var defs []map[string]any
	if err := json.Unmarshal([]byte(raw), &defs); err != nil {
		return nil // unparseable JSON: not our problem to solve here
	}
	for _, d := range defs {
		priv, ok := d["privileged"].(bool)
		if !ok {
			continue // absent or non-bool: cannot be proven privileged
		}
		if priv {
			name, _ := d["name"].(string)
			detail := "container is privileged"
			if name != "" {
				detail = "container " + name + " is privileged"
			}
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-302",
				Title:       (ecsPrivilegedContainer{}).Title(),
				Description: (ecsPrivilegedContainer{}).Description(),
				Severity:    ir.SeverityHigh,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "container_definitions[].privileged",
					Span:      evidenceSpan(span, r.Span),
					Actual:    "true (" + detail + ")",
					Expected:  "privileged omitted or false",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-303: ECR repository without image scanning
// ---------------------------------------------------------------------------

type ecrNoImageScanning struct{}

func (ecrNoImageScanning) ID() string { return "AEGIS-AWS-303" }
func (ecrNoImageScanning) Title() string {
	return "ECR repository without image scanning"
}
func (ecrNoImageScanning) Description() string {
	return "Without image_scanning_configuration { scan_on_push = true }, " +
		"vulnerable images are pushed and deployed without any scan."
}
func (ecrNoImageScanning) Severity() ir.Severity { return ir.SeverityMedium }

func (ecrNoImageScanning) AppliesTo(resType string) bool {
	return resType == "aws_ecr_repository"
}

func (ecrNoImageScanning) Check(r ir.Resource) []ir.Finding {
	cfg, span, present, known := getBlocks(r, "image_scanning_configuration")
	mk := func(actual string) []ir.Finding {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-303",
			Title:       (ecrNoImageScanning{}).Title(),
			Description: (ecrNoImageScanning{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "image_scanning_configuration.scan_on_push",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "image_scanning_configuration { scan_on_push = true }",
			},
		}}
	}
	if !present {
		return mk("block absent (scanning disabled by default)")
	}
	if !known {
		return nil // unresolved block: cannot decide
	}
	for _, c := range cfg {
		on, _, spresent, sknown := blockBool(c, "scan_on_push")
		if spresent && !sknown {
			return nil // unresolved: cannot decide
		}
		if !spresent || !on {
			return mk(boolActual(spresent, on))
		}
		return nil // scan_on_push = true
	}
	return nil
}

func boolActual(present, val bool) string {
	if !present {
		return "absent (disabled by default)"
	}
	if val {
		return "true"
	}
	return "false"
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-304: EKS cluster without secrets encryption
// ---------------------------------------------------------------------------

type eksNoSecretsEncryption struct{}

func (eksNoSecretsEncryption) ID() string { return "AEGIS-AWS-304" }
func (eksNoSecretsEncryption) Title() string {
	return "EKS cluster without secrets encryption"
}
func (eksNoSecretsEncryption) Description() string {
	return "Without an encryption_config block, Kubernetes secrets are stored " +
		"in etcd encrypted only with an AWS-owned key instead of a " +
		"customer-managed KMS key."
}
func (eksNoSecretsEncryption) Severity() ir.Severity { return ir.SeverityHigh }

func (eksNoSecretsEncryption) AppliesTo(resType string) bool {
	return resType == "aws_eks_cluster"
}

func (eksNoSecretsEncryption) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getBlocks(r, "encryption_config")
	if present {
		return nil // configured (block present; unresolved blocks stay silent)
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-304",
		Title:       (eksNoSecretsEncryption{}).Title(),
		Description: (eksNoSecretsEncryption{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "encryption_config",
			Span:      r.Span,
			Actual:    "absent (secrets use AWS-owned key)",
			Expected:  "encryption_config { provider { key_arn = ... } }",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-305: EKS cluster with public endpoint
// ---------------------------------------------------------------------------

type eksPublicEndpoint struct{}

func (eksPublicEndpoint) ID() string { return "AEGIS-AWS-305" }
func (eksPublicEndpoint) Title() string {
	return "EKS cluster with public endpoint"
}
func (eksPublicEndpoint) Description() string {
	return "vpc_config.endpoint_public_access = true exposes the Kubernetes " +
		"API server to the public internet."
}
func (eksPublicEndpoint) Severity() ir.Severity { return ir.SeverityHigh }

func (eksPublicEndpoint) AppliesTo(resType string) bool {
	return resType == "aws_eks_cluster"
}

func (eksPublicEndpoint) Check(r ir.Resource) []ir.Finding {
	cfg, _, present, known := getBlocks(r, "vpc_config")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	for _, c := range cfg {
		pub, pspan, ppresent, pknown := blockBool(c, "endpoint_public_access")
		if ppresent && !pknown {
			return nil // unresolved: cannot decide
		}
		if ppresent && pub {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-305",
				Title:       (eksPublicEndpoint{}).Title(),
				Description: (eksPublicEndpoint{}).Description(),
				Severity:    ir.SeverityHigh,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "vpc_config.endpoint_public_access",
					Span:      evidenceSpan(pspan, r.Span),
					Actual:    "true",
					Expected:  "false (private endpoint)",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-306: EKS cluster without control plane logging
// ---------------------------------------------------------------------------

type eksNoControlPlaneLogging struct{}

func (eksNoControlPlaneLogging) ID() string { return "AEGIS-AWS-306" }
func (eksNoControlPlaneLogging) Title() string {
	return "EKS cluster without control plane logging"
}
func (eksNoControlPlaneLogging) Description() string {
	return "Without enabled_cluster_log_types, EKS control-plane audit and " +
		"authenticator logs are not sent to CloudWatch, blinding incident " +
		"response."
}
func (eksNoControlPlaneLogging) Severity() ir.Severity { return ir.SeverityMedium }

func (eksNoControlPlaneLogging) AppliesTo(resType string) bool {
	return resType == "aws_eks_cluster"
}

func (eksNoControlPlaneLogging) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["enabled_cluster_log_types"]
	mk := func(actual string) []ir.Finding {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-306",
			Title:       (eksNoControlPlaneLogging{}).Title(),
			Description: (eksNoControlPlaneLogging{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "enabled_cluster_log_types",
				Span:      evidenceSpan(v.Span, r.Span),
				Actual:    actual,
				Expected:  "non-empty list of log types",
			},
		}}
	}
	if !ok {
		return mk("absent (no control plane logs)")
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	l, ok := v.AsList()
	if !ok {
		return nil // unexpected shape: cannot decide
	}
	if len(l) == 0 {
		return mk("empty list (no control plane logs)")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-307: Lambda function env vars without KMS
// ---------------------------------------------------------------------------

type lambdaEnvNoKMS struct{}

func (lambdaEnvNoKMS) ID() string { return "AEGIS-AWS-307" }
func (lambdaEnvNoKMS) Title() string {
	return "Lambda function env vars without KMS"
}
func (lambdaEnvNoKMS) Description() string {
	return "An environment block with variables but no kms_key_arn leaves " +
		"environment variables (often secrets) encrypted only with an " +
		"AWS-owned key."
}
func (lambdaEnvNoKMS) Severity() ir.Severity { return ir.SeverityHigh }

func (lambdaEnvNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}

func (lambdaEnvNoKMS) Check(r ir.Resource) []ir.Finding {
	env, span, present, known := getBlocks(r, "environment")
	if !present || !known {
		return nil // no environment block (or unresolved): no finding
	}
	for _, e := range env {
		vv, ok := e["variables"]
		if !ok || !vv.Known {
			continue // no provable variables in this block
		}
		vars, ok := vv.AsMap()
		if !ok || len(vars) == 0 {
			continue // no variables: nothing to protect
		}
		key, _, kpresent, kknown := blockString(e, "kms_key_arn")
		if kpresent && !kknown {
			return nil // unresolved: cannot decide
		}
		if kpresent && strings.TrimSpace(key) != "" {
			return nil // KMS key configured
		}
		actual := "absent (AWS-owned key)"
		if kpresent {
			actual = "empty (AWS-owned key)"
		}
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-307",
			Title:       (lambdaEnvNoKMS{}).Title(),
			Description: (lambdaEnvNoKMS{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "environment.kms_key_arn",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "kms_key_arn set to a customer-managed key",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-308: Lambda without active X-Ray tracing
// ---------------------------------------------------------------------------

type lambdaNoActiveTracing struct{}

func (lambdaNoActiveTracing) ID() string { return "AEGIS-AWS-308" }
func (lambdaNoActiveTracing) Title() string {
	return "Lambda without active X-Ray tracing"
}
func (lambdaNoActiveTracing) Description() string {
	return "Without tracing_config { mode = \"Active\" }, Lambda invocations " +
		"are not traced in X-Ray, reducing observability of failures and " +
		"latency."
}
func (lambdaNoActiveTracing) Severity() ir.Severity { return ir.SeverityMedium }

func (lambdaNoActiveTracing) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}

func (lambdaNoActiveTracing) Check(r ir.Resource) []ir.Finding {
	cfg, span, present, known := getBlocks(r, "tracing_config")
	mk := func(actual string) []ir.Finding {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-308",
			Title:       (lambdaNoActiveTracing{}).Title(),
			Description: (lambdaNoActiveTracing{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "tracing_config.mode",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "tracing_config { mode = \"Active\" }",
			},
		}}
	}
	if !present {
		return mk("block absent (tracing not active)")
	}
	if !known {
		return nil // unresolved block: cannot decide
	}
	for _, c := range cfg {
		mode, _, mpresent, mknown := blockString(c, "mode")
		if mpresent && !mknown {
			return nil // unresolved: cannot decide
		}
		if !mpresent {
			return mk("mode absent (tracing not active)")
		}
		if strings.EqualFold(strings.TrimSpace(mode), "Active") {
			return nil // Active
		}
		return mk("mode = " + strconv.Quote(mode))
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-309: Deprecated launch configuration in use
// ---------------------------------------------------------------------------

type launchConfigurationDeprecated struct{}

func (launchConfigurationDeprecated) ID() string { return "AEGIS-AWS-309" }
func (launchConfigurationDeprecated) Title() string {
	return "Deprecated launch configuration in use"
}
func (launchConfigurationDeprecated) Description() string {
	return "aws_launch_configuration is deprecated by AWS; migrate to " +
		"aws_launch_template, which receives new features and supports " +
		"versioning."
}
func (launchConfigurationDeprecated) Severity() ir.Severity {
	return ir.SeverityMedium
}

func (launchConfigurationDeprecated) AppliesTo(resType string) bool {
	return resType == "aws_launch_configuration"
}

func (launchConfigurationDeprecated) Check(r ir.Resource) []ir.Finding {
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-309",
		Title:       (launchConfigurationDeprecated{}).Title(),
		Description: (launchConfigurationDeprecated{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "resource",
			Span:      r.Span,
			Actual:    "aws_launch_configuration (deprecated)",
			Expected:  "aws_launch_template",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-310: EC2 instance without detailed monitoring
// ---------------------------------------------------------------------------

type ec2NoDetailedMonitoring struct{}

func (ec2NoDetailedMonitoring) ID() string { return "AEGIS-AWS-310" }
func (ec2NoDetailedMonitoring) Title() string {
	return "EC2 instance without detailed monitoring"
}
func (ec2NoDetailedMonitoring) Description() string {
	return "With monitoring absent or false (the provider default), the " +
		"instance ships only basic 5-minute CloudWatch metrics, delaying " +
		"detection of performance and availability issues."
}
func (ec2NoDetailedMonitoring) Severity() ir.Severity { return ir.SeverityMedium }

func (ec2NoDetailedMonitoring) AppliesTo(resType string) bool {
	return resType == "aws_instance"
}

func (ec2NoDetailedMonitoring) Check(r ir.Resource) []ir.Finding {
	mon, span, present, known := getBool(r, "monitoring")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && mon {
		return nil // detailed monitoring enabled
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: disabled)"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-310",
		Title:       (ec2NoDetailedMonitoring{}).Title(),
		Description: (ec2NoDetailedMonitoring{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "monitoring",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "monitoring = true",
		},
	}}
}
