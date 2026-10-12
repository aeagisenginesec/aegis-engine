package aws

import (
	"encoding/json"
	"strings"

	"aegis/internal/ir"
)

// Analytics & ML rules (AEGIS-AWS-361–370).

// AnalyticsRules returns the analytics & ML rules in ID order.
func AnalyticsRules() []ir.Rule {
	return []ir.Rule{
		emrNoAtRestEncryption{},    // AEGIS-AWS-361
		emrVisibleToAllUsers{},     // AEGIS-AWS-362
		athenaNoResultEncryption{}, // AEGIS-AWS-363
		glueCatalogNoSSEKMS{},      // AEGIS-AWS-364
		firehoseNoEncryption{},     // AEGIS-AWS-365
		sagemakerNotebookNoKMS{},   // AEGIS-AWS-366
		sagemakerEndpointNoKMS{},   // AEGIS-AWS-367
		fsxWindowsNoKMS{},          // AEGIS-AWS-368
		fsxLustreNoKMS{},           // AEGIS-AWS-369
		sagemakerDomainNoKMS{},     // AEGIS-AWS-370
	}
}

// kmsKeyAbsentFinding is a shared helper for the KMS-absent rules: fires
// when attr is absent or empty, stays silent on unknown. The description
// documents the AWS-managed-key caveat: absent means AWS-managed
// encryption, which this rule treats as insufficient (customer-managed
// key required), consistent with rule 313.
func kmsKeyAbsentFinding(rule ir.Rule, r ir.Resource, attr string) []ir.Finding {
	key, span, present, known := getString(r, attr)
	if !present {
		return []ir.Finding{{
			RuleID:      rule.ID(),
			Title:       rule.Title(),
			Description: rule.Description(),
			Severity:    rule.Severity(),
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: attr,
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent (AWS-managed key, no customer control)",
				Expected:  attr + " set to a customer-managed KMS key",
			},
		}}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if strings.TrimSpace(key) == "" {
		return []ir.Finding{{
			RuleID:      rule.ID(),
			Title:       rule.Title(),
			Description: rule.Description(),
			Severity:    rule.Severity(),
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: attr,
				Span:      evidenceSpan(span, r.Span),
				Actual:    "empty",
				Expected:  attr + " set to a customer-managed KMS key",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-361: EMR security configuration without at-rest encryption
// ---------------------------------------------------------------------------

type emrNoAtRestEncryption struct{}

func (emrNoAtRestEncryption) ID() string { return "AEGIS-AWS-361" }
func (emrNoAtRestEncryption) Title() string {
	return "EMR security configuration without at-rest encryption"
}
func (emrNoAtRestEncryption) Description() string {
	return "An EMR security configuration whose EncryptionConfiguration does " +
		"not set EnableAtRestEncryption = true leaves cluster data " +
		"unencrypted at rest."
}
func (emrNoAtRestEncryption) Severity() ir.Severity { return ir.SeverityHigh }

func (emrNoAtRestEncryption) AppliesTo(resType string) bool {
	return resType == "aws_emr_security_configuration"
}

func (emrNoAtRestEncryption) Check(r ir.Resource) []ir.Finding {
	raw, span, present, known := getString(r, "configuration")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil // unparseable JSON: not our problem to solve here
	}
	enc, ok := cfg["EncryptionConfiguration"].(map[string]any)
	if !ok {
		return nil // block absent from the JSON: cannot prove disabled
	}
	enabled, ok := enc["EnableAtRestEncryption"].(bool)
	if !ok {
		return nil // flag absent or non-bool: cannot decide
	}
	if enabled {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-361",
		Title:       (emrNoAtRestEncryption{}).Title(),
		Description: (emrNoAtRestEncryption{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "configuration.EncryptionConfiguration.EnableAtRestEncryption",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "EnableAtRestEncryption = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-362: EMR cluster visible to all users
// ---------------------------------------------------------------------------

type emrVisibleToAllUsers struct{}

func (emrVisibleToAllUsers) ID() string { return "AEGIS-AWS-362" }
func (emrVisibleToAllUsers) Title() string {
	return "EMR cluster visible to all users"
}
func (emrVisibleToAllUsers) Description() string {
	return "visible_to_all_users = true grants every IAM user in the account " +
		"visibility into the EMR cluster and its job data."
}
func (emrVisibleToAllUsers) Severity() ir.Severity { return ir.SeverityMedium }

func (emrVisibleToAllUsers) AppliesTo(resType string) bool {
	return resType == "aws_emr_cluster"
}

func (emrVisibleToAllUsers) Check(r ir.Resource) []ir.Finding {
	vis, span, _, known := getBool(r, "visible_to_all_users")
	if !known || !vis {
		return nil // absent, false, or unresolved: cannot prove exposure
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-362",
		Title:       (emrVisibleToAllUsers{}).Title(),
		Description: (emrVisibleToAllUsers{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "visible_to_all_users",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false (or omitted)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-363: Athena workgroup without result encryption
// ---------------------------------------------------------------------------

type athenaNoResultEncryption struct{}

func (athenaNoResultEncryption) ID() string { return "AEGIS-AWS-363" }
func (athenaNoResultEncryption) Title() string {
	return "Athena workgroup without result encryption"
}
func (athenaNoResultEncryption) Description() string {
	return "An Athena workgroup whose query results are not encrypted " +
		"(encryption_option = NONE or no encryption_configuration) stores " +
		"plaintext query output in S3."
}
func (athenaNoResultEncryption) Severity() ir.Severity { return ir.SeverityHigh }

func (athenaNoResultEncryption) AppliesTo(resType string) bool {
	return resType == "aws_athena_workgroup"
}

func (athenaNoResultEncryption) Check(r ir.Resource) []ir.Finding {
	mk := func(actual string, span ir.Span) []ir.Finding {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-363",
			Title:       (athenaNoResultEncryption{}).Title(),
			Description: (athenaNoResultEncryption{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "configuration.result_configuration.encryption_configuration.encryption_option",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "encryption_option = SSE_S3 or SSE_KMS",
			},
		}}
	}
	// Walk the nested block chain defensively; any unknown link aborts.
	confs, _, present, known := getBlocks(r, "configuration")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || len(confs) == 0 {
		return mk("configuration block absent", r.Span)
	}
	for _, conf := range confs {
		results := blockList(conf, "result_configuration")
		if results == nil {
			// A blockList nil return is ambiguous (absent vs unknown); the
			// block map itself is known here, so nil means the key is
			// absent or malformed — treat absent as unencrypted.
			if _, ok := conf["result_configuration"]; !ok {
				return mk("result_configuration block absent", r.Span)
			}
			return nil // present but unresolvable shape: cannot decide
		}
		for _, res := range results {
			encs := blockList(res, "encryption_configuration")
			if encs == nil {
				if _, ok := res["encryption_configuration"]; !ok {
					return mk("encryption_configuration block absent", r.Span)
				}
				return nil
			}
			for _, enc := range encs {
				opt, _, opresent, oknown := blockString(enc, "encryption_option")
				if opresent && !oknown {
					return nil // unresolved: cannot decide
				}
				if !opresent {
					return mk("encryption_option absent", r.Span)
				}
				if strings.EqualFold(strings.TrimSpace(opt), "NONE") {
					return mk("NONE", r.Span)
				}
				return nil // SSE_S3 / SSE_KMS: encrypted
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-364: Glue data catalog without SSE-KMS
// ---------------------------------------------------------------------------

type glueCatalogNoSSEKMS struct{}

func (glueCatalogNoSSEKMS) ID() string { return "AEGIS-AWS-364" }
func (glueCatalogNoSSEKMS) Title() string {
	return "Glue data catalog without SSE-KMS encryption"
}
func (glueCatalogNoSSEKMS) Description() string {
	return "The Glue data catalog should encrypt at rest with SSE-KMS " +
		"(catalog_encryption_mode = SSE-KMS); anything else leaves catalog " +
		"metadata under weaker protection."
}
func (glueCatalogNoSSEKMS) Severity() ir.Severity { return ir.SeverityHigh }

func (glueCatalogNoSSEKMS) AppliesTo(resType string) bool {
	return resType == "aws_glue_data_catalog_encryption_settings"
}

func (glueCatalogNoSSEKMS) Check(r ir.Resource) []ir.Finding {
	mk := func(actual string, span ir.Span) []ir.Finding {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-364",
			Title:       (glueCatalogNoSSEKMS{}).Title(),
			Description: (glueCatalogNoSSEKMS{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "data_catalog_encryption_settings.encryption_at_rest.catalog_encryption_mode",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "catalog_encryption_mode = SSE-KMS",
			},
		}}
	}
	sets, _, present, known := getBlocks(r, "data_catalog_encryption_settings")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || len(sets) == 0 {
		return mk("data_catalog_encryption_settings block absent", r.Span)
	}
	for _, s := range sets {
		rests := blockList(s, "encryption_at_rest")
		if rests == nil {
			if _, ok := s["encryption_at_rest"]; !ok {
				return mk("encryption_at_rest block absent", r.Span)
			}
			return nil
		}
		for _, rest := range rests {
			mode, _, mpresent, mknown := blockString(rest, "catalog_encryption_mode")
			if mpresent && !mknown {
				return nil // unresolved: cannot decide
			}
			if !mpresent {
				return mk("catalog_encryption_mode absent", r.Span)
			}
			if !strings.EqualFold(strings.TrimSpace(mode), "SSE-KMS") {
				return mk(mode, r.Span)
			}
			return nil // SSE-KMS: compliant
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-365: Kinesis Firehose delivery stream without encryption
// ---------------------------------------------------------------------------

type firehoseNoEncryption struct{}

func (firehoseNoEncryption) ID() string { return "AEGIS-AWS-365" }
func (firehoseNoEncryption) Title() string {
	return "Kinesis Firehose delivery stream without server-side encryption"
}
func (firehoseNoEncryption) Description() string {
	return "A Firehose delivery stream without server_side_encryption " +
		"{ enabled = true } stores delivered records unencrypted."
}
func (firehoseNoEncryption) Severity() ir.Severity { return ir.SeverityMedium }

func (firehoseNoEncryption) AppliesTo(resType string) bool {
	return resType == "aws_kinesis_firehose_delivery_stream"
}

func (firehoseNoEncryption) Check(r ir.Resource) []ir.Finding {
	return nestedEnabledCheck(r, "server_side_encryption", "AEGIS-AWS-365",
		(firehoseNoEncryption{}).Title(), (firehoseNoEncryption{}).Description(),
		ir.SeverityMedium, "absent (provider default: disabled)")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-366: SageMaker notebook instance unencrypted
// ---------------------------------------------------------------------------

type sagemakerNotebookNoKMS struct{}

func (sagemakerNotebookNoKMS) ID() string { return "AEGIS-AWS-366" }
func (sagemakerNotebookNoKMS) Title() string {
	return "SageMaker notebook instance without customer-managed KMS key"
}
func (sagemakerNotebookNoKMS) Description() string {
	return "A SageMaker notebook instance with no kms_key_id relies on the " +
		"AWS-managed key, offering no customer control over key rotation or " +
		"revocation. Set kms_key_id to a customer-managed KMS key."
}
func (sagemakerNotebookNoKMS) Severity() ir.Severity { return ir.SeverityHigh }

func (sagemakerNotebookNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_sagemaker_notebook_instance"
}

func (sagemakerNotebookNoKMS) Check(r ir.Resource) []ir.Finding {
	return kmsKeyAbsentFinding(sagemakerNotebookNoKMS{}, r, "kms_key_id")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-367: SageMaker endpoint configuration without KMS
// ---------------------------------------------------------------------------

type sagemakerEndpointNoKMS struct{}

func (sagemakerEndpointNoKMS) ID() string { return "AEGIS-AWS-367" }
func (sagemakerEndpointNoKMS) Title() string {
	return "SageMaker endpoint configuration without customer-managed KMS key"
}
func (sagemakerEndpointNoKMS) Description() string {
	return "A SageMaker endpoint configuration with no kms_key_arn relies on " +
		"the AWS-managed key, offering no customer control over key rotation " +
		"or revocation. Set kms_key_arn to a customer-managed KMS key."
}
func (sagemakerEndpointNoKMS) Severity() ir.Severity { return ir.SeverityMedium }

func (sagemakerEndpointNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_sagemaker_endpoint_configuration"
}

func (sagemakerEndpointNoKMS) Check(r ir.Resource) []ir.Finding {
	return kmsKeyAbsentFinding(sagemakerEndpointNoKMS{}, r, "kms_key_arn")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-368: FSx Windows file system unencrypted
// ---------------------------------------------------------------------------

type fsxWindowsNoKMS struct{}

func (fsxWindowsNoKMS) ID() string { return "AEGIS-AWS-368" }
func (fsxWindowsNoKMS) Title() string {
	return "FSx Windows file system without customer-managed KMS key"
}
func (fsxWindowsNoKMS) Description() string {
	return "An FSx Windows file system with no kms_key_id relies on the " +
		"AWS-managed key, offering no customer control over key rotation or " +
		"revocation. Set kms_key_id to a customer-managed KMS key."
}
func (fsxWindowsNoKMS) Severity() ir.Severity { return ir.SeverityHigh }

func (fsxWindowsNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_fsx_windows_file_system"
}

func (fsxWindowsNoKMS) Check(r ir.Resource) []ir.Finding {
	return kmsKeyAbsentFinding(fsxWindowsNoKMS{}, r, "kms_key_id")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-369: FSx Lustre file system unencrypted
// ---------------------------------------------------------------------------

type fsxLustreNoKMS struct{}

func (fsxLustreNoKMS) ID() string { return "AEGIS-AWS-369" }
func (fsxLustreNoKMS) Title() string {
	return "FSx Lustre file system without customer-managed KMS key"
}
func (fsxLustreNoKMS) Description() string {
	return "An FSx Lustre file system with no kms_key_id relies on the " +
		"AWS-managed key, offering no customer control over key rotation or " +
		"revocation. Set kms_key_id to a customer-managed KMS key."
}
func (fsxLustreNoKMS) Severity() ir.Severity { return ir.SeverityHigh }

func (fsxLustreNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_fsx_lustre_file_system"
}

func (fsxLustreNoKMS) Check(r ir.Resource) []ir.Finding {
	return kmsKeyAbsentFinding(fsxLustreNoKMS{}, r, "kms_key_id")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-370: SageMaker domain without KMS
// ---------------------------------------------------------------------------

type sagemakerDomainNoKMS struct{}

func (sagemakerDomainNoKMS) ID() string { return "AEGIS-AWS-370" }
func (sagemakerDomainNoKMS) Title() string {
	return "SageMaker domain without customer-managed KMS key"
}
func (sagemakerDomainNoKMS) Description() string {
	return "A SageMaker domain with no kms_key_id relies on the AWS-managed " +
		"key, offering no customer control over key rotation or revocation. " +
		"Set kms_key_id to a customer-managed KMS key."
}
func (sagemakerDomainNoKMS) Severity() ir.Severity { return ir.SeverityMedium }

func (sagemakerDomainNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_sagemaker_domain"
}

func (sagemakerDomainNoKMS) Check(r ir.Resource) []ir.Finding {
	return kmsKeyAbsentFinding(sagemakerDomainNoKMS{}, r, "kms_key_id")
}
