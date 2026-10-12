// Package docker implements the Dockerfile rule pack for Aegis.
//
// The dockerfile adapter produces one docker_stage resource per build
// stage. These rules inspect base images, USER directives, ENV secrets,
// exposed ports, and RUN hygiene. Missing or unknown values never produce
// a finding: rules report only explicit misconfigurations. Secret values
// are never stored in resources and never appear in evidence.
package docker

import (
	"fmt"
	"strings"

	"aegis/internal/ir"
)

// Rules returns every rule in the Docker pack, in ID order.
func Rules() []ir.Rule {
	base := []ir.Rule{
		latestTag{},         // AEGIS-DOCKER-001
		noNonRootUser{},     // AEGIS-DOCKER-002
		envSecrets{},        // AEGIS-DOCKER-003
		addInsteadOfCopy{},  // AEGIS-DOCKER-004
		noHealthcheck{},     // AEGIS-DOCKER-005
		exposedSSH{},        // AEGIS-DOCKER-006
		aptNoRecommends{},   // AEGIS-DOCKER-007
		aptUpdateNoClean{},  // AEGIS-DOCKER-008
		sudoUsage{},         // AEGIS-DOCKER-009
		untrustedRegistry{}, // AEGIS-DOCKER-010
	}
	return append(base, extraRules()...) // AEGIS-DOCKER-011..035
}

// appliesToDocker reports whether a resource type belongs to this pack.
func appliesToDocker(resType string) bool { return resType == "docker_stage" }

func getString(r ir.Resource, name string) (string, ir.Span, bool, bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return "", ir.Span{}, false, false
	}
	s, kok := v.AsString()
	return s, v.Span, true, kok
}

func getBool(r ir.Resource, name string) (bool, ir.Span, bool, bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return false, ir.Span{}, false, false
	}
	b, kok := v.AsBool()
	return b, v.Span, true, kok
}

func getList(r ir.Resource, name string) ([]ir.Value, ir.Span, bool, bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return nil, ir.Span{}, false, false
	}
	l, kok := v.AsList()
	return l, v.Span, true, kok
}

func spanOr(span, fallback ir.Span) ir.Span {
	if span.File == "" {
		return fallback
	}
	return span
}

func finding(ruleID, title, desc string, sev ir.Severity, r ir.Resource, attr string, span ir.Span, actual, expected string) ir.Finding {
	return ir.Finding{
		RuleID:      ruleID,
		Title:       title,
		Description: desc,
		Severity:    sev,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      spanOr(span, r.Span),
			Actual:    actual,
			Expected:  expected,
		},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-001: base image uses :latest (medium)
// ---------------------------------------------------------------------------

type latestTag struct{}

func (latestTag) ID() string { return "AEGIS-DOCKER-001" }
func (latestTag) Title() string {
	return "Base image uses :latest tag"
}
func (latestTag) Description() string {
	return "Pinning :latest (or omitting the tag, which implies :latest) " +
		"makes builds non-reproducible and can silently pull a new, " +
		"vulnerable image. Pin an explicit version tag or digest."
}
func (latestTag) Severity() ir.Severity         { return ir.SeverityMedium }
func (latestTag) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (latestTag) Check(r ir.Resource) []ir.Finding {
	rule := latestTag{}
	img, ispan, present, known := getString(r, "base_image")
	if !present || !known || strings.TrimSpace(img) == "" {
		return nil
	}
	// A digest-pinned image is reproducible even without a tag.
	if strings.Contains(img, "@sha256:") {
		return nil
	}
	tag, _, tpresent, tknown := getString(r, "base_tag")
	if tpresent && !tknown {
		return nil
	}
	if !tpresent || strings.TrimSpace(tag) == "" || strings.EqualFold(tag, "latest") {
		actual := "tag :latest"
		if !tpresent || strings.TrimSpace(tag) == "" {
			actual = "no tag (implicit :latest)"
		}
		return []ir.Finding{finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "base_image", ispan, img+" ("+actual+")",
			"pinned version tag (e.g. ubuntu:22.04) or digest",
		)}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-002: no USER directive / USER root (high)
// ---------------------------------------------------------------------------

type noNonRootUser struct{}

func (noNonRootUser) ID() string { return "AEGIS-DOCKER-002" }
func (noNonRootUser) Title() string {
	return "Container runs as root"
}
func (noNonRootUser) Description() string {
	return "Without a USER directive the container runs as root; an explicit " +
		"USER root (or 0) is the same risk. A container breakout then yields " +
		"host root. Switch to a non-root user."
}
func (noNonRootUser) Severity() ir.Severity         { return ir.SeverityHigh }
func (noNonRootUser) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (noNonRootUser) Check(r ir.Resource) []ir.Finding {
	rule := noNonRootUser{}
	user, uspan, present, known := getString(r, "user")
	if present && !known {
		return nil
	}
	if !present || strings.TrimSpace(user) == "" {
		return []ir.Finding{finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "user", r.Span, "no USER directive (defaults to root)",
			"USER <non-root>",
		)}
	}
	u := strings.ToLower(strings.TrimSpace(user))
	if u == "root" || u == "0" {
		return []ir.Finding{finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "user", uspan, user,
			"USER <non-root>",
		)}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-003: secrets in ENV (high)
// ---------------------------------------------------------------------------

type envSecrets struct{}

func (envSecrets) ID() string { return "AEGIS-DOCKER-003" }
func (envSecrets) Title() string {
	return "Secret in ENV directive"
}
func (envSecrets) Description() string {
	return "ENV values are baked into the image layers and visible to " +
		"anyone who can pull the image (docker history, inspect). " +
		"Inject secrets at runtime instead. The secret value is never " +
		"shown in findings."
}
func (envSecrets) Severity() ir.Severity         { return ir.SeverityHigh }
func (envSecrets) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (envSecrets) Check(r ir.Resource) []ir.Finding {
	rule := envSecrets{}
	secrets, _, present, known := getList(r, "env_secrets")
	if !present || !known {
		return nil
	}
	var out []ir.Finding
	for _, s := range secrets {
		m, ok := s.AsMap()
		if !ok {
			continue
		}
		nv, ok := m["name"]
		if !ok {
			continue
		}
		name, nok := nv.AsString()
		if !nok || strings.TrimSpace(name) == "" {
			continue
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "env", nv.Span,
			fmt.Sprintf("%s=[REDACTED]", name), // value never disclosed
			"inject secrets at runtime (build args with --secret, runtime env, secret mounts)",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-004: ADD instead of COPY (low)
// ---------------------------------------------------------------------------

type addInsteadOfCopy struct{}

func (addInsteadOfCopy) ID() string { return "AEGIS-DOCKER-004" }
func (addInsteadOfCopy) Title() string {
	return "ADD used instead of COPY"
}
func (addInsteadOfCopy) Description() string {
	return "ADD fetches remote URLs and auto-extracts archives, which can " +
		"pull untrusted content into the image. Prefer COPY for local files."
}
func (addInsteadOfCopy) Severity() ir.Severity         { return ir.SeverityLow }
func (addInsteadOfCopy) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (addInsteadOfCopy) Check(r ir.Resource) []ir.Finding {
	rule := addInsteadOfCopy{}
	uses, _, present, known := getBool(r, "uses_add")
	if !present || !known || !uses {
		return nil
	}
	span := r.Span
	if v, ok := r.Attributes["add_span"]; ok {
		span = v.Span
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "ADD", span, "ADD instruction present",
		"COPY for local files",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-005: no HEALTHCHECK (low)
// ---------------------------------------------------------------------------

type noHealthcheck struct{}

func (noHealthcheck) ID() string { return "AEGIS-DOCKER-005" }
func (noHealthcheck) Title() string {
	return "No HEALTHCHECK directive"
}
func (noHealthcheck) Description() string {
	return "Without a HEALTHCHECK the orchestrator cannot tell a wedged " +
		"container from a healthy one, delaying restarts and hiding " +
		"compromise-induced hangs."
}
func (noHealthcheck) Severity() ir.Severity         { return ir.SeverityLow }
func (noHealthcheck) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (noHealthcheck) Check(r ir.Resource) []ir.Finding {
	rule := noHealthcheck{}
	hc, _, present, known := getBool(r, "has_healthcheck")
	if present && !known {
		return nil
	}
	if present && hc {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "HEALTHCHECK", r.Span, "absent",
		"HEALTHCHECK instruction",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-006: exposed port 22 (medium)
// ---------------------------------------------------------------------------

type exposedSSH struct{}

func (exposedSSH) ID() string { return "AEGIS-DOCKER-006" }
func (exposedSSH) Title() string {
	return "SSH port exposed"
}
func (exposedSSH) Description() string {
	return "EXPOSE 22 suggests SSH runs inside the container. Containers " +
		"should be immutable and managed via the orchestrator, not SSH; " +
		"an SSH daemon widens the attack surface."
}
func (exposedSSH) Severity() ir.Severity         { return ir.SeverityMedium }
func (exposedSSH) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (exposedSSH) Check(r ir.Resource) []ir.Finding {
	rule := exposedSSH{}
	ports, _, present, known := getList(r, "exposed_ports")
	if !present || !known {
		return nil
	}
	var out []ir.Finding
	for _, p := range ports {
		s, ok := p.AsString()
		if !ok || strings.TrimSpace(s) != "22" {
			continue
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "EXPOSE", p.Span, "22",
			"no SSH in containers",
		))
	}
	return out
}

// runCommands returns the RUN command bodies of a stage.
func runCommands(r ir.Resource) []ir.Value {
	cmds, _, present, known := getList(r, "run_commands")
	if !present || !known {
		return nil
	}
	return cmds
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-007: apt-get without --no-install-recommends (low)
// ---------------------------------------------------------------------------

type aptNoRecommends struct{}

func (aptNoRecommends) ID() string { return "AEGIS-DOCKER-007" }
func (aptNoRecommends) Title() string {
	return "apt-get install without --no-install-recommends"
}
func (aptNoRecommends) Description() string {
	return "Installing recommended packages bloats the image with " +
		"unneeded software, enlarging the attack surface. Pass " +
		"--no-install-recommends to apt-get install."
}
func (aptNoRecommends) Severity() ir.Severity         { return ir.SeverityLow }
func (aptNoRecommends) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (aptNoRecommends) Check(r ir.Resource) []ir.Finding {
	rule := aptNoRecommends{}
	var out []ir.Finding
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		if aptInstallWithoutNoRecommends(cmd) {
			out = append(out, finding(
				rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
				r, "RUN", c.Span, "apt-get install without --no-install-recommends",
				"apt-get install --no-install-recommends",
			))
		}
	}
	return out
}

// aptInstallWithoutNoRecommends detects `apt-get install` lacking the flag.
// apt / aptitude variants are out of scope by design.
func aptInstallWithoutNoRecommends(cmd string) bool {
	lower := strings.ToLower(cmd)
	if strings.Contains(lower, "--no-install-recommends") {
		return false
	}
	// Split on shell command separators and check each segment.
	for _, seg := range strings.FieldsFunc(lower, func(r rune) bool {
		return r == ';' || r == '&' || r == '|' || r == '\n'
	}) {
		toks := strings.Fields(seg)
		for i := 0; i < len(toks); i++ {
			if toks[i] != "apt-get" {
				continue
			}
			// Look ahead for "install" before the next apt-get or end.
			for j := i + 1; j < len(toks) && toks[j] != "apt-get"; j++ {
				if toks[j] == "install" {
					return true
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-008: apt-get update without cleanup (low)
// ---------------------------------------------------------------------------

type aptUpdateNoClean struct{}

func (aptUpdateNoClean) ID() string { return "AEGIS-DOCKER-008" }
func (aptUpdateNoClean) Title() string {
	return "apt-get update without cache cleanup"
}
func (aptUpdateNoClean) Description() string {
	return "apt-get update leaves package lists in the image layer. " +
		"Remove /var/lib/apt/lists/* in the same RUN to keep layers lean."
}
func (aptUpdateNoClean) Severity() ir.Severity         { return ir.SeverityLow }
func (aptUpdateNoClean) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (aptUpdateNoClean) Check(r ir.Resource) []ir.Finding {
	rule := aptUpdateNoClean{}
	var out []ir.Finding
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		lower := strings.ToLower(cmd)
		if !strings.Contains(lower, "apt-get update") {
			continue
		}
		if strings.Contains(lower, "rm -rf /var/lib/apt/lists") ||
			strings.Contains(lower, "rm -rf /var/lib/apt/lists/*") {
			continue
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "RUN", c.Span, "apt-get update without rm -rf /var/lib/apt/lists/*",
			"clean package lists in the same RUN layer",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-009: sudo usage (low)
// ---------------------------------------------------------------------------

type sudoUsage struct{}

func (sudoUsage) ID() string { return "AEGIS-DOCKER-009" }
func (sudoUsage) Title() string {
	return "sudo used in build"
}
func (sudoUsage) Description() string {
	return "RUN executes as root by default, so sudo is unnecessary; its " +
		"presence suggests confused privilege boundaries or a copied " +
		"snippet. Drop sudo and rely on USER instead."
}
func (sudoUsage) Severity() ir.Severity         { return ir.SeverityLow }
func (sudoUsage) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (sudoUsage) Check(r ir.Resource) []ir.Finding {
	rule := sudoUsage{}
	used, _, present, known := getBool(r, "sudo_used")
	if !present || !known || !used {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "RUN", r.Span, "sudo invoked in RUN",
		"run as root by default; use USER for runtime privilege drop",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-010: base image from untrusted registry (medium)
// ---------------------------------------------------------------------------

type untrustedRegistry struct{}

func (untrustedRegistry) ID() string { return "AEGIS-DOCKER-010" }
func (untrustedRegistry) Title() string {
	return "Base image from untrusted registry"
}
func (untrustedRegistry) Description() string {
	return "Only official Docker Hub library images are trusted by " +
		"default. Images from other registries or namespaces have " +
		"unknown provenance and may carry backdoors. Prefer official " +
		"images or pin digests from registries you control."
}
func (untrustedRegistry) Severity() ir.Severity         { return ir.SeverityMedium }
func (untrustedRegistry) AppliesTo(resType string) bool { return appliesToDocker(resType) }

// trustedRegistryHosts are the Docker Hub endpoints.
var trustedRegistryHosts = map[string]bool{
	"docker.io":            true,
	"index.docker.io":      true,
	"registry-1.docker.io": true,
}

func (untrustedRegistry) Check(r ir.Resource) []ir.Finding {
	rule := untrustedRegistry{}
	img, ispan, present, known := getString(r, "base_image")
	if !present || !known || strings.TrimSpace(img) == "" {
		return nil
	}
	img = strings.TrimSpace(img)
	// Digest-pinned images from any registry are out of scope: the
	// digest, not the registry, is the trust anchor.
	if strings.Contains(img, "@sha256:") {
		return nil
	}
	host, path := splitRegistry(img)
	if host == "" {
		// Implicit docker.io. Trusted only when it is an official
		// library image (single path component, e.g. "ubuntu").
		if !strings.Contains(path, "/") {
			return nil
		}
		return []ir.Finding{finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "base_image", ispan, img,
			"official library image (e.g. ubuntu:22.04) or digest-pinned image",
		)}
	}
	if trustedRegistryHosts[strings.ToLower(host)] && strings.HasPrefix(path, "library/") {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "base_image", ispan, img,
		"official library image or digest-pinned image from a controlled registry",
	)}
}

// splitRegistry splits an image reference into registry host and remainder.
// A host is present when the first path component contains '.' or ':' or
// is "localhost".
func splitRegistry(img string) (host, rest string) {
	// Strip tag and digest first.
	if i := strings.Index(img, "@"); i >= 0 {
		img = img[:i]
	}
	if slash := strings.LastIndex(img, "/"); slash >= 0 {
		if colon := strings.LastIndex(img, ":"); colon > slash {
			img = img[:colon]
		}
	} else if colon := strings.LastIndex(img, ":"); colon >= 0 {
		img = img[:colon]
	}
	parts := strings.SplitN(img, "/", 2)
	if len(parts) == 1 {
		return "", parts[0]
	}
	first := parts[0]
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		return first, parts[1]
	}
	return "", img
}
