// Package supplychain — extended rules (AEGIS-SC-002 through AEGIS-SC-009).
//
// These rules target supply-chain attack surfaces that traditional IaC
// scanners under-cover: container image provenance, user_data script
// injection, unpinned AMIs, provisioner abuse, external data sources,
// insecure download URLs, and third-party Lambda layers.
//
// CONTRACT (same as the rest of the pack): unknown values yield no finding.
// Rules never panic on unexpected shapes. Findings are deterministic.
package supplychain

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"aegis/internal/ir"
)

// supplyChainExtraRules returns AEGIS-SC-002 through AEGIS-SC-009 in ID order.
func supplyChainExtraRules() []ir.Rule {
	return []ir.Rule{
		lambdaPublicECRImage{},
		userDataCurlPipe{},
		unpinnedAMI{},
		remoteExecProvisioner{},
		nullResourceLocalExec{},
		externalDataSource{},
		userDataHTTPDownload{},
		lambdaLayerUnknownAccount{},
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// strAttr extracts a known string attribute; ok=false when absent or unknown.
func strAttr(r ir.Resource, name string) (string, ir.Span, bool) {
	v, present := r.Attributes[name]
	if !present {
		return "", ir.Span{}, false
	}
	s, known := v.AsString()
	if !known {
		return "", ir.Span{}, false
	}
	return s, v.Span, true
}

// strListAttr extracts a known list of strings; ok=false when absent,
// unknown, or any element is not a known string.
func strListAttr(r ir.Resource, name string) ([]string, ir.Span, bool) {
	v, present := r.Attributes[name]
	if !present {
		return nil, ir.Span{}, false
	}
	l, known := v.AsList()
	if !known {
		return nil, ir.Span{}, false
	}
	out := make([]string, 0, len(l))
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			return nil, ir.Span{}, false
		}
		out = append(out, s)
	}
	return out, v.Span, true
}

// blockMaps extracts nested blocks for name as []map[string]ir.Value.
// Returns nil when absent, unknown, or not a block shape.
func blockMaps(r ir.Resource, name string) []map[string]ir.Value {
	v, present := r.Attributes[name]
	if !present || !v.Known {
		return nil
	}
	if m, ok := v.AsMap(); ok {
		return []map[string]ir.Value{m}
	}
	l, ok := v.AsList()
	if !ok {
		return nil
	}
	var out []map[string]ir.Value
	for _, item := range l {
		if m, ok := item.AsMap(); ok {
			out = append(out, m)
		}
	}
	return out
}

// evSpan prefers the attribute span, falling back to the resource span.
func evSpan(attrSpan, resSpan ir.Span) ir.Span {
	if attrSpan.File != "" {
		return attrSpan
	}
	return resSpan
}

// ---------------------------------------------------------------------------
// AEGIS-SC-002: Lambda function using a public ECR image
// ---------------------------------------------------------------------------

type lambdaPublicECRImage struct{}

func (lambdaPublicECRImage) ID() string { return "AEGIS-SC-002" }
func (lambdaPublicECRImage) Title() string {
	return "Lambda function uses a public ECR image"
}
func (lambdaPublicECRImage) Description() string {
	return "An aws_lambda_function with package_type=Image pulls its container " +
		"image from public ECR (public.ecr.aws). Public images can be replaced " +
		"or typosquatted; pin images by digest and prefer private repositories. " +
		"Unknown or unresolved image URIs yield no finding."
}
func (lambdaPublicECRImage) Severity() ir.Severity { return ir.SeverityHigh }
func (lambdaPublicECRImage) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}

func (lambdaPublicECRImage) Check(r ir.Resource) []ir.Finding {
	img, ok := r.Attr("image_uri")
	if !ok {
		return nil
	}
	uri, known := img.AsString()
	if !known {
		return nil // unresolved: cannot decide
	}
	lower := strings.ToLower(strings.TrimSpace(uri))
	if !strings.Contains(lower, "public.ecr.aws") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-SC-002",
		Title:       (lambdaPublicECRImage{}).Title(),
		Description: (lambdaPublicECRImage{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "image_uri",
			Span:      evSpan(img.Span, r.Span),
			Actual:    "public ECR image: " + redactURI(uri),
			Expected:  "image from a private, access-controlled repository pinned by digest",
		},
	}}
}

// redactURI keeps the registry host but drops any path/tag that might be sensitive.
func redactURI(uri string) string {
	if i := strings.Index(uri, "/"); i >= 0 {
		return uri[:i+1] + "<redacted>"
	}
	return "<redacted>"
}

// ---------------------------------------------------------------------------
// AEGIS-SC-003: user_data with curl|bash / wget|sh pipe
// ---------------------------------------------------------------------------

var pipeToShell = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(bash|sh)\b`)

type userDataCurlPipe struct{}

func (userDataCurlPipe) ID() string { return "AEGIS-SC-003" }
func (userDataCurlPipe) Title() string {
	return "user_data pipes a remote download into a shell"
}
func (userDataCurlPipe) Description() string {
	return "user_data containing 'curl ... | bash' or 'wget ... | sh' executes " +
		"arbitrary remote code at instance launch with no integrity check. " +
		"Vendor the script, verify a checksum or signature, or use a " +
		"configuration management system instead. Unknown user_data yields " +
		"no finding."
}
func (userDataCurlPipe) Severity() ir.Severity { return ir.SeverityHigh }
func (userDataCurlPipe) AppliesTo(resType string) bool {
	switch resType {
	case "aws_instance", "aws_launch_template", "aws_launch_configuration",
		"aws_autoscaling_group":
		return true
	}
	return false
}

func (userDataCurlPipe) Check(r ir.Resource) []ir.Finding {
	ud, span, ok := strAttr(r, "user_data")
	if !ok {
		// also check base64-encoded variant
		ud, span, ok = strAttr(r, "user_data_base64")
		if !ok {
			return nil
		}
	}
	if !pipeToShell.MatchString(ud) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-SC-003",
		Title:       (userDataCurlPipe{}).Title(),
		Description: (userDataCurlPipe{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "user_data",
			Span:      evSpan(span, r.Span),
			Actual:    "remote download piped to shell",
			Expected:  "no curl|bash or wget|sh patterns in user_data",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-SC-004: unpinned AMI (contains "latest")
// ---------------------------------------------------------------------------

type unpinnedAMI struct{}

func (unpinnedAMI) ID() string    { return "AEGIS-SC-004" }
func (unpinnedAMI) Title() string { return "EC2 instance uses an unpinned AMI" }
func (unpinnedAMI) Description() string {
	return "The ami attribute references a floating tag (contains \"latest\"). " +
		"Floating AMI references make launches non-reproducible and let an " +
		"attacker who compromises the AMI pipeline inject code into future " +
		"instances. Pin AMIs by ID (ami-...). Variable or data-source " +
		"references are unresolved and yield no finding."
}
func (unpinnedAMI) Severity() ir.Severity         { return ir.SeverityMedium }
func (unpinnedAMI) AppliesTo(resType string) bool { return resType == "aws_instance" }

func (unpinnedAMI) Check(r ir.Resource) []ir.Finding {
	ami, span, ok := strAttr(r, "ami")
	if !ok {
		return nil // absent or unresolved: cannot decide
	}
	if !strings.Contains(strings.ToLower(ami), "latest") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-SC-004",
		Title:       (unpinnedAMI{}).Title(),
		Description: (unpinnedAMI{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "ami",
			Span:      evSpan(span, r.Span),
			Actual:    "floating AMI reference containing \"latest\"",
			Expected:  "pinned AMI ID (ami-...) or versioned data source",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-SC-005: provisioner with remote-exec (inline commands)
// ---------------------------------------------------------------------------

type remoteExecProvisioner struct{}

func (remoteExecProvisioner) ID() string { return "AEGIS-SC-005" }
func (remoteExecProvisioner) Title() string {
	return "Provisioner executes remote commands"
}
func (remoteExecProvisioner) Description() string {
	return "A provisioner block with an 'inline' command list executes " +
		"arbitrary commands on the remote host during apply (the remote-exec " +
		"pattern). Provisioners are a last resort: they run outside the " +
		"declarative model, often with elevated privileges, and their " +
		"failures leave infrastructure half-configured. Prefer user_data, " +
		"configuration management, or immutable images."
}
func (remoteExecProvisioner) Severity() ir.Severity { return ir.SeverityMedium }
func (remoteExecProvisioner) AppliesTo(resType string) bool {
	// Applies to any resource type; provisioner blocks are the signal.
	// The engine calls Check for every resource; we return nil fast when
	// no provisioner attribute exists.
	return true
}

func (remoteExecProvisioner) Check(r ir.Resource) []ir.Finding {
	// Skip the synthetic terraform_* resources and the advisory/provider types.
	if strings.HasPrefix(r.Type, "terraform_") || r.Type == "aegis_advisory" {
		return nil
	}
	provs := blockMaps(r, "provisioner")
	if len(provs) == 0 {
		return nil
	}
	var out []ir.Finding
	for _, p := range provs {
		inline, ok := p["inline"]
		if !ok || !inline.Known {
			continue
		}
		if _, ok := inline.AsList(); !ok {
			continue
		}
		// 'inline' is the remote-exec signature (local-exec uses 'command').
		span := inline.Span
		if span.File == "" {
			span = r.Span
		}
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-SC-005",
			Title:       (remoteExecProvisioner{}).Title(),
			Description: (remoteExecProvisioner{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "provisioner.inline",
				Span:      span,
				Actual:    "provisioner with inline remote commands",
				Expected:  "no provisioners; use user_data or config management",
			},
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-SC-006: null_resource with local-exec provisioner
// ---------------------------------------------------------------------------

type nullResourceLocalExec struct{}

func (nullResourceLocalExec) ID() string { return "AEGIS-SC-006" }
func (nullResourceLocalExec) Title() string {
	return "null_resource executes local commands"
}
func (nullResourceLocalExec) Description() string {
	return "A null_resource with a local-exec provisioner runs arbitrary " +
		"commands on the machine executing Terraform. This is a common " +
		"exfiltration and persistence vector in supply-chain attacks: a " +
		"compromised module can steal credentials or implant backdoors on " +
		"the operator's workstation or CI runner. Avoid null_resource " +
		"provisioners entirely."
}
func (nullResourceLocalExec) Severity() ir.Severity { return ir.SeverityHigh }
func (nullResourceLocalExec) AppliesTo(resType string) bool {
	return resType == "null_resource"
}

func (nullResourceLocalExec) Check(r ir.Resource) []ir.Finding {
	provs := blockMaps(r, "provisioner")
	if len(provs) == 0 {
		return nil
	}
	var out []ir.Finding
	for _, p := range provs {
		cmd, ok := p["command"]
		if !ok || !cmd.Known {
			continue
		}
		if _, ok := cmd.AsString(); !ok {
			continue
		}
		// 'command' is the local-exec signature.
		span := cmd.Span
		if span.File == "" {
			span = r.Span
		}
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-SC-006",
			Title:       (nullResourceLocalExec{}).Title(),
			Description: (nullResourceLocalExec{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "provisioner.command",
				Span:      span,
				Actual:    "null_resource with local-exec provisioner",
				Expected:  "no local-exec provisioners on null_resource",
			},
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-SC-007: external data source (arbitrary program execution)
// ---------------------------------------------------------------------------

type externalDataSource struct{}

func (externalDataSource) ID() string { return "AEGIS-SC-007" }
func (externalDataSource) Title() string {
	return "External data source executes an arbitrary program"
}
func (externalDataSource) Description() string {
	return "A data \"external\" block runs an arbitrary program during plan " +
		"and apply, on the operator's machine, with the operator's " +
		"credentials in the environment. A compromised module can use this " +
		"to exfiltrate secrets or establish persistence. Avoid data " +
		"\"external\"; prefer native data sources."
}
func (externalDataSource) Severity() ir.Severity { return ir.SeverityMedium }
func (externalDataSource) AppliesTo(resType string) bool {
	return resType == "terraform_data"
}

func (externalDataSource) Check(r ir.Resource) []ir.Finding {
	// Adapter contract: data "external" "name" arrives as
	// terraform_data with Name "external.<name>". The block type alone is
	// the risk signal: it executes an arbitrary program during plan/apply.
	if !strings.HasPrefix(r.Name, "external.") {
		return nil
	}
	span := r.Span
	if v, present := r.Attributes["program"]; present && v.Span.File != "" {
		span = v.Span
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-SC-007",
		Title:       (externalDataSource{}).Title(),
		Description: (externalDataSource{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "program",
			Span:      span,
			Actual:    "data \"external\" block executes an external program",
			Expected:  "no data \"external\" blocks",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-SC-008: HTTP (not HTTPS) download URL in user_data
// ---------------------------------------------------------------------------

var httpURL = regexp.MustCompile(`(?i)\bhttp://[^\s"'<>]+`)

type userDataHTTPDownload struct{}

func (userDataHTTPDownload) ID() string { return "AEGIS-SC-008" }
func (userDataHTTPDownload) Title() string {
	return "user_data downloads over plain HTTP"
}
func (userDataHTTPDownload) Description() string {
	return "user_data contains an http:// URL. Plain-HTTP downloads are " +
		"vulnerable to man-in-the-middle tampering: an attacker on the " +
		"network path can substitute a malicious payload that the instance " +
		"then executes at boot. Use https:// URLs and verify checksums. " +
		"Unknown user_data yields no finding."
}
func (userDataHTTPDownload) Severity() ir.Severity { return ir.SeverityLow }
func (userDataHTTPDownload) AppliesTo(resType string) bool {
	switch resType {
	case "aws_instance", "aws_launch_template", "aws_launch_configuration",
		"aws_autoscaling_group":
		return true
	}
	return false
}

func (userDataHTTPDownload) Check(r ir.Resource) []ir.Finding {
	ud, span, ok := strAttr(r, "user_data")
	if !ok {
		ud, span, ok = strAttr(r, "user_data_base64")
		if !ok {
			return nil
		}
	}
	m := httpURL.FindString(ud)
	if m == "" {
		return nil
	}
	host := m
	if i := strings.Index(m, "/"); i >= 0 {
		host = m[:i]
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-SC-008",
		Title:       (userDataHTTPDownload{}).Title(),
		Description: (userDataHTTPDownload{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "user_data",
			Span:      evSpan(span, r.Span),
			Actual:    "plain-HTTP URL: " + host,
			Expected:  "https:// URLs for all downloads in user_data",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-SC-009: Lambda layer from an unrecognized account
// ---------------------------------------------------------------------------

var layerAccountRe = regexp.MustCompile(`^arn:[^:]*:[^:]*:[^:]*:(\d{12}):layer:`)

// trustedLayerAccounts is intentionally small and documented. AWS does not
// publish a canonical list of managed layer publishers; accounts outside
// this list are flagged for review, not declared malicious.
var trustedLayerAccounts = map[string]bool{}

type lambdaLayerUnknownAccount struct{}

func (lambdaLayerUnknownAccount) ID() string { return "AEGIS-SC-009" }
func (lambdaLayerUnknownAccount) Title() string {
	return "Lambda function uses a layer from an unrecognized account"
}
func (lambdaLayerUnknownAccount) Description() string {
	return "An aws_lambda_function references a Lambda layer published by an " +
		"account outside the trusted publisher list. Third-party layers run " +
		"with the function's privileges; a compromised or typosquatted layer " +
		"is a direct code-execution vector. Vet the publisher and pin the " +
		"layer version. Unresolvable layer lists yield no finding."
}
func (lambdaLayerUnknownAccount) Severity() ir.Severity { return ir.SeverityMedium }
func (lambdaLayerUnknownAccount) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}

func (lambdaLayerUnknownAccount) Check(r ir.Resource) []ir.Finding {
	layers, span, ok := strListAttr(r, "layers")
	if !ok || len(layers) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []ir.Finding
	for _, l := range layers {
		m := layerAccountRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue // not an ARN with an account: cannot decide
		}
		acct := m[1]
		if trustedLayerAccounts[acct] || seen[acct] {
			continue
		}
		seen[acct] = true
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-SC-009",
			Title:       (lambdaLayerUnknownAccount{}).Title(),
			Description: (lambdaLayerUnknownAccount{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "layers",
				Span:      evSpan(span, r.Span),
				Actual:    fmt.Sprintf("layer from unrecognized account %s", acct),
				Expected:  "layers only from vetted, trusted publisher accounts",
			},
		})
	}
	// Deterministic: sort by account so multi-layer findings are stable.
	sort.Slice(out, func(i, j int) bool {
		return out[i].Evidence.Actual < out[j].Evidence.Actual
	})
	return out
}
