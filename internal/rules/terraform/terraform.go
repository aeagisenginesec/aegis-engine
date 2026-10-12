// Package terraform implements the AEGIS-TF rule pack: Terraform
// configuration security — misconfigurations of the Terraform tooling
// itself (backends, provider pinning, version constraints) rather than
// of cloud resources. These are vulnerability classes most IaC scanners
// cover poorly or not at all.
//
// The terraform adapter exposes `terraform { }`, nested `backend`, and
// `provider` blocks as synthetic ir.Resources of types "terraform_config",
// "terraform_backend", and "terraform_provider".
package terraform

import (
	"strings"

	"aegis/internal/ir"
)

// PackName identifies the Terraform configuration rule pack.
const PackName = "aegis-terraform"

// TerraformRules returns every rule in the pack, in ID order.
func TerraformRules() []ir.Rule {
	return []ir.Rule{
		tfBackendNoEncrypt{},    // AEGIS-TF-001
		tfBackendNoLocking{},    // AEGIS-TF-002
		tfProviderUnpinned{},    // AEGIS-TF-003
		tfVersionUnpinned{},     // AEGIS-TF-004
		tfBackendHTTP{},         // AEGIS-TF-005
		tfBackendLocal{},        // AEGIS-TF-006
		tfNoRequiredProviders{}, // AEGIS-TF-007
		tfSkipCredValidation{},  // AEGIS-TF-008
	}
}

// ---------------------------------------------------------------------------
// helpers (pack-local; mirror the aws pack conventions)
// ---------------------------------------------------------------------------

// attrString extracts a known string attribute.
func attrString(r ir.Resource, name string) (string, ir.Span, bool, bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return "", ir.Span{}, false, false
	}
	s, kok := v.AsString()
	return s, v.Span, true, kok
}

// attrBool extracts a known bool attribute (tri-state).
func attrBool(r ir.Resource, name string) (bool, ir.Span, bool, bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return false, ir.Span{}, false, false
	}
	b, kok := v.AsBool()
	return b, v.Span, true, kok
}

// getBlocks returns nested blocks for a resource attribute.
func getBlocks(r ir.Resource, name string) (blks []map[string]ir.Value, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return nil, ir.Span{}, false, false
	}
	if !v.Known {
		return nil, v.Span, true, false
	}
	if m, ok := v.AsMap(); ok {
		return []map[string]ir.Value{m}, v.Span, true, true
	}
	l, ok := v.AsList()
	if !ok {
		return nil, v.Span, true, false
	}
	out := make([]map[string]ir.Value, 0, len(l))
	for _, item := range l {
		m, ok := item.AsMap()
		if !ok {
			continue // unexpected shape: skip defensively, never panic
		}
		out = append(out, m)
	}
	return out, v.Span, true, true
}

// blockString extracts a known string from a block map.
func blockString(m map[string]ir.Value, name string) (string, ir.Span, bool, bool) {
	v, ok := m[name]
	if !ok {
		return "", ir.Span{}, false, false
	}
	s, kok := v.AsString()
	return s, v.Span, true, kok
}

// evidenceSpan prefers the attribute span, falling back to the resource span.
func evidenceSpan(attrSpan, resSpan ir.Span) ir.Span {
	if attrSpan.File != "" {
		return attrSpan
	}
	return resSpan
}

func finding(rule ir.Rule, r ir.Resource, attr string, span ir.Span, actual, expected string) ir.Finding {
	return ir.Finding{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  expected,
		},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-TF-001: S3 backend without state encryption
// ---------------------------------------------------------------------------

type tfBackendNoEncrypt struct{}

func (tfBackendNoEncrypt) ID() string { return "AEGIS-TF-001" }
func (tfBackendNoEncrypt) Title() string {
	return "Terraform S3 backend without state encryption"
}
func (tfBackendNoEncrypt) Description() string {
	return "The S3 backend stores the entire state file — including secrets — " +
		"in the bucket. The encrypt argument defaults to false, so an S3 " +
		"backend without encrypt = true keeps state in plaintext at rest."
}
func (tfBackendNoEncrypt) Severity() ir.Severity { return ir.SeverityHigh }
func (tfBackendNoEncrypt) AppliesTo(resType string) bool {
	return resType == "terraform_backend"
}
func (tfBackendNoEncrypt) Check(r ir.Resource) []ir.Finding {
	if r.Name != "s3" {
		return nil
	}
	enc, espan, present, known := attrBool(r, "encrypt")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || !enc {
		actual := "absent (defaults to false)"
		if present {
			actual = "false"
		}
		return []ir.Finding{finding(tfBackendNoEncrypt{}, r, "encrypt",
			espan, actual, "encrypt = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-TF-002: S3 backend without state locking
// ---------------------------------------------------------------------------

type tfBackendNoLocking struct{}

func (tfBackendNoLocking) ID() string { return "AEGIS-TF-002" }
func (tfBackendNoLocking) Title() string {
	return "Terraform S3 backend without state locking"
}
func (tfBackendNoLocking) Description() string {
	return "Without a DynamoDB lock table, concurrent Terraform runs can " +
		"corrupt the state file. An S3 backend without dynamodb_table has " +
		"no state locking."
}
func (tfBackendNoLocking) Severity() ir.Severity { return ir.SeverityHigh }
func (tfBackendNoLocking) AppliesTo(resType string) bool {
	return resType == "terraform_backend"
}
func (tfBackendNoLocking) Check(r ir.Resource) []ir.Finding {
	if r.Name != "s3" {
		return nil
	}
	tbl, tspan, present, known := attrString(r, "dynamodb_table")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || strings.TrimSpace(tbl) == "" {
		actual := "absent"
		if present {
			actual = "empty"
		}
		return []ir.Finding{finding(tfBackendNoLocking{}, r, "dynamodb_table",
			tspan, actual, "dynamodb_table set to a lock table")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-TF-003: Unpinned provider version
// ---------------------------------------------------------------------------

type tfProviderUnpinned struct{}

func (tfProviderUnpinned) ID() string { return "AEGIS-TF-003" }
func (tfProviderUnpinned) Title() string {
	return "Terraform provider without pinned version"
}
func (tfProviderUnpinned) Description() string {
	return "A required_providers entry without a version constraint — or " +
		"with an open-ended constraint like \">= 1.0\" — lets a future " +
		"provider release silently change plan/apply behavior, including " +
		"security-relevant defaults."
}
func (tfProviderUnpinned) Severity() ir.Severity { return ir.SeverityMedium }
func (tfProviderUnpinned) AppliesTo(resType string) bool {
	return resType == "terraform_config"
}

// allowsBreakingChange reports whether a version constraint permits
// unbounded upgrades: ">="/"x.y" with no upper bound.
func allowsBreakingChange(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	// Split multi-constraints ("..., ..."); an upper bound anywhere saves it.
	for _, part := range strings.Split(v, ",") {
		if strings.Contains(part, "<") {
			return false
		}
	}
	for _, part := range strings.Split(v, ",") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(p, ">=") || strings.HasPrefix(p, ">") {
			return true
		}
	}
	return false
}

func (tfProviderUnpinned) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "required_providers")
	if !present || !known {
		return nil // TF-007 covers the missing block; unknown: cannot decide
	}
	var out []ir.Finding
	for _, b := range blks {
		name, _, npresent, nknown := blockString(b, "name")
		if !npresent || !nknown || name == "" {
			continue
		}
		ver, vspan, vpresent, vknown := blockString(b, "version")
		attr := "required_providers." + name + ".version"
		switch {
		case !vpresent || strings.TrimSpace(ver) == "":
			out = append(out, finding(tfProviderUnpinned{}, r, attr,
				vspan, "absent", "version constraint (e.g. \"~> 5.0\")"))
		case !vknown:
			// unresolved: cannot decide
		case allowsBreakingChange(ver):
			out = append(out, finding(tfProviderUnpinned{}, r, attr,
				vspan, ver, "bounded version constraint (e.g. \"~> 5.0\" or \">= 5.0, < 6.0\")"))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-TF-004: Unpinned Terraform version
// ---------------------------------------------------------------------------

type tfVersionUnpinned struct{}

func (tfVersionUnpinned) ID() string { return "AEGIS-TF-004" }
func (tfVersionUnpinned) Title() string {
	return "Terraform CLI version not pinned"
}
func (tfVersionUnpinned) Description() string {
	return "Without terraform.required_version, any CLI version may run " +
		"this configuration; behavior and provider-protocol differences " +
		"across versions can change what gets applied."
}
func (tfVersionUnpinned) Severity() ir.Severity { return ir.SeverityMedium }
func (tfVersionUnpinned) AppliesTo(resType string) bool {
	return resType == "terraform_config"
}
func (tfVersionUnpinned) Check(r ir.Resource) []ir.Finding {
	v, present := r.Attributes["required_version"]
	if !present {
		return []ir.Finding{finding(tfVersionUnpinned{}, r, "required_version",
			ir.Span{}, "absent", "required_version constraint (e.g. \">= 1.5.0\")")}
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-TF-005: Backend over plaintext HTTP
// ---------------------------------------------------------------------------

type tfBackendHTTP struct{}

func (tfBackendHTTP) ID() string { return "AEGIS-TF-005" }
func (tfBackendHTTP) Title() string {
	return "Terraform backend using plaintext HTTP"
}
func (tfBackendHTTP) Description() string {
	return "A backend address over http:// sends the state file — including " +
		"secrets — in cleartext on the network."
}
func (tfBackendHTTP) Severity() ir.Severity { return ir.SeverityHigh }
func (tfBackendHTTP) AppliesTo(resType string) bool {
	return resType == "terraform_backend"
}
func (tfBackendHTTP) Check(r ir.Resource) []ir.Finding {
	addr, aspan, present, known := attrString(r, "address")
	if !present || !known {
		return nil // unresolved or absent: cannot decide
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(addr)), "http://") {
		return []ir.Finding{finding(tfBackendHTTP{}, r, "address",
			aspan, addr, "https:// address")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-TF-006: Local backend (state on disk in plaintext)
// ---------------------------------------------------------------------------

type tfBackendLocal struct{}

func (tfBackendLocal) ID() string { return "AEGIS-TF-006" }
func (tfBackendLocal) Title() string {
	return "Terraform local backend stores state in plaintext"
}
func (tfBackendLocal) Description() string {
	return "The local backend keeps terraform.tfstate on disk unencrypted. " +
		"State files contain secrets in cleartext; a remote encrypted " +
		"backend should be used instead."
}
func (tfBackendLocal) Severity() ir.Severity { return ir.SeverityMedium }
func (tfBackendLocal) AppliesTo(resType string) bool {
	return resType == "terraform_backend"
}
func (tfBackendLocal) Check(r ir.Resource) []ir.Finding {
	if r.Name != "local" {
		return nil
	}
	return []ir.Finding{finding(tfBackendLocal{}, r, "backend",
		ir.Span{}, "local", "remote state backend (e.g. s3 with encryption)")}
}

// ---------------------------------------------------------------------------
// AEGIS-TF-007: Missing required_providers block
// ---------------------------------------------------------------------------

type tfNoRequiredProviders struct{}

func (tfNoRequiredProviders) ID() string { return "AEGIS-TF-007" }
func (tfNoRequiredProviders) Title() string {
	return "Terraform configuration without required_providers"
}
func (tfNoRequiredProviders) Description() string {
	return "Without a required_providers block, provider sources and " +
		"versions are implicit; Terraform may select unexpected providers " +
		"or versions."
}
func (tfNoRequiredProviders) Severity() ir.Severity { return ir.SeverityLow }
func (tfNoRequiredProviders) AppliesTo(resType string) bool {
	return resType == "terraform_config"
}
func (tfNoRequiredProviders) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "required_providers")
	if !present || (known && len(blks) == 0) {
		return []ir.Finding{finding(tfNoRequiredProviders{}, r, "required_providers",
			ir.Span{}, "absent", "required_providers block with pinned versions")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-TF-008: Provider skips credential validation
// ---------------------------------------------------------------------------

type tfSkipCredValidation struct{}

func (tfSkipCredValidation) ID() string { return "AEGIS-TF-008" }
func (tfSkipCredValidation) Title() string {
	return "Terraform provider skips credentials validation"
}
func (tfSkipCredValidation) Description() string {
	return "skip_credentials_validation = true disables the provider's " +
		"startup credential checks, hiding misconfigured or expired " +
		"credentials until apply time — or masking use of unintended accounts."
}
func (tfSkipCredValidation) Severity() ir.Severity { return ir.SeverityMedium }
func (tfSkipCredValidation) AppliesTo(resType string) bool {
	return resType == "terraform_provider"
}
func (tfSkipCredValidation) Check(r ir.Resource) []ir.Finding {
	skip, sspan, present, known := attrBool(r, "skip_credentials_validation")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if skip {
		return []ir.Finding{finding(tfSkipCredValidation{}, r,
			"skip_credentials_validation", sspan, "true",
			"skip_credentials_validation = false (or absent)")}
	}
	return nil
}

// Rules is an alias for TerraformRules for registry compatibility.
func Rules() []ir.Rule { return TerraformRules() }
