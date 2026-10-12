// Package compose implements the Docker Compose rule pack for Aegis.
//
// The compose adapter produces one compose_service resource per service.
// These rules inspect privilege escalation vectors (privileged, cap_add,
// host namespaces), dangerous mounts, baked-in secrets, root execution,
// and floating image tags. Missing or unknown values never produce a
// finding. Secret values are never stored in resources or evidence.
package compose

import (
	"fmt"
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// Rules returns every rule in the Compose pack, in ID order.
func Rules() []ir.Rule {
	return []ir.Rule{
		privilegedService{},  // AEGIS-COMPOSE-001
		dangerousCaps{},      // AEGIS-COMPOSE-002
		hostNamespaces{},     // AEGIS-COMPOSE-003
		dockerSockMount{},    // AEGIS-COMPOSE-004
		sensitiveHostMount{}, // AEGIS-COMPOSE-005
		composeEnvSecrets{},  // AEGIS-COMPOSE-006
		composeRootUser{},    // AEGIS-COMPOSE-007
		composeLatestTag{},   // AEGIS-COMPOSE-008
	}
}

// appliesToCompose reports whether a resource type belongs to this pack.
func appliesToCompose(resType string) bool { return resType == "compose_service" }

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

func spanOr(span, fallback ir.Span) ir.Span {
	if span.File == "" {
		return fallback
	}
	return span
}

// ---------------------------------------------------------------------------
// AEGIS-COMPOSE-001: privileged: true (high)
// ---------------------------------------------------------------------------

type privilegedService struct{}

func (privilegedService) ID() string { return "AEGIS-COMPOSE-001" }
func (privilegedService) Title() string {
	return "Service runs privileged"
}
func (privilegedService) Description() string {
	return "privileged: true disables all container isolation: the " +
		"service gets every capability and full device access, so a " +
		"compromise is a host compromise. Grant only the capabilities " +
		"the service needs via cap_add."
}
func (privilegedService) Severity() ir.Severity         { return ir.SeverityHigh }
func (privilegedService) AppliesTo(resType string) bool { return appliesToCompose(resType) }

func (privilegedService) Check(r ir.Resource) []ir.Finding {
	rule := privilegedService{}
	priv, pspan, present, known := getBool(r, "privileged")
	if !present || !known || !priv {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "privileged", pspan, "privileged: true",
		"least-privilege cap_add instead of privileged",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-COMPOSE-002: dangerous cap_add (high)
// ---------------------------------------------------------------------------

type dangerousCaps struct{}

func (dangerousCaps) ID() string { return "AEGIS-COMPOSE-002" }
func (dangerousCaps) Title() string {
	return "Dangerous Linux capability granted"
}
func (dangerousCaps) Description() string {
	return "The granted capability breaks container isolation: ALL " +
		"grants everything, SYS_ADMIN is near-root, NET_ADMIN can " +
		"reconfigure host networking, SYS_PTRACE can inspect host " +
		"processes, and DAC_OVERRIDE bypasses file permissions. " +
		"Grant only the minimal capabilities required."
}
func (dangerousCaps) Severity() ir.Severity         { return ir.SeverityHigh }
func (dangerousCaps) AppliesTo(resType string) bool { return appliesToCompose(resType) }

var dangerousCapabilities = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true,
	"SYS_PTRACE": true, "DAC_OVERRIDE": true,
}

func (dangerousCaps) Check(r ir.Resource) []ir.Finding {
	rule := dangerousCaps{}
	caps, _, present, known := getList(r, "cap_add")
	if !present || !known {
		return nil
	}
	var out []ir.Finding
	for _, c := range caps {
		s, ok := c.AsString()
		if !ok {
			continue
		}
		if dangerousCapabilities[strings.ToUpper(strings.TrimSpace(s))] {
			out = append(out, finding(
				rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
				r, "cap_add", c.Span, s,
				"minimal capability set; avoid ALL/SYS_ADMIN/NET_ADMIN/SYS_PTRACE/DAC_OVERRIDE",
			))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-COMPOSE-003: host network/PID namespaces (medium)
// ---------------------------------------------------------------------------

type hostNamespaces struct{}

func (hostNamespaces) ID() string { return "AEGIS-COMPOSE-003" }
func (hostNamespaces) Title() string {
	return "Service shares host namespaces"
}
func (hostNamespaces) Description() string {
	return "network_mode: host (or pid: host) drops network/process " +
		"isolation: the service sees host interfaces and processes, " +
		"bypassing network policies. Use explicit port publishing and " +
		"keep the default namespaces."
}
func (hostNamespaces) Severity() ir.Severity         { return ir.SeverityMedium }
func (hostNamespaces) AppliesTo(resType string) bool { return appliesToCompose(resType) }

func (hostNamespaces) Check(r ir.Resource) []ir.Finding {
	rule := hostNamespaces{}
	var out []ir.Finding
	if nm, nspan, present, known := getString(r, "network_mode"); present && known &&
		strings.EqualFold(strings.TrimSpace(nm), "host") {
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "network_mode", nspan, "host",
			"published ports on the default bridge network",
		))
	}
	if pid, pspan, present, known := getString(r, "pid"); present && known &&
		strings.EqualFold(strings.TrimSpace(pid), "host") {
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "pid", pspan, "host",
			"default PID namespace",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-COMPOSE-004: Docker socket mounted (high)
// ---------------------------------------------------------------------------

type dockerSockMount struct{}

func (dockerSockMount) ID() string { return "AEGIS-COMPOSE-004" }
func (dockerSockMount) Title() string {
	return "Docker socket mounted into service"
}
func (dockerSockMount) Description() string {
	return "Mounting the Docker socket gives the service full control " +
		"of the daemon: it can start privileged containers and escape " +
		"to the host trivially. Use the socket only in dedicated, " +
		"audited tooling with a read-only proxy."
}
func (dockerSockMount) Severity() ir.Severity         { return ir.SeverityHigh }
func (dockerSockMount) AppliesTo(resType string) bool { return appliesToCompose(resType) }

func isDockerSock(p string) bool {
	return p == "/var/run/docker.sock" || p == "/run/docker.sock" ||
		strings.HasSuffix(p, "/docker.sock")
}

func (dockerSockMount) Check(r ir.Resource) []ir.Finding {
	rule := dockerSockMount{}
	vols, _, present, known := getList(r, "volumes")
	if !present || !known {
		return nil
	}
	var out []ir.Finding
	for _, v := range vols {
		s, ok := v.AsString()
		if !ok || !isDockerSock(s) {
			continue
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "volumes", v.Span, "mounts "+s,
			"no Docker socket mount; use a socket proxy if needed",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-COMPOSE-005: sensitive host path mounted (high)
// ---------------------------------------------------------------------------

type sensitiveHostMount struct{}

func (sensitiveHostMount) ID() string { return "AEGIS-COMPOSE-005" }
func (sensitiveHostMount) Title() string {
	return "Sensitive host path mounted"
}
func (sensitiveHostMount) Description() string {
	return "Mounting host system paths exposes host configuration, " +
		"credentials, or the whole filesystem to the service. Mount " +
		"only dedicated data directories, read-only where possible."
}
func (sensitiveHostMount) Severity() ir.Severity         { return ir.SeverityHigh }
func (sensitiveHostMount) AppliesTo(resType string) bool { return appliesToCompose(resType) }

// sensitiveHostRoots are host paths that must never be bind-mounted.
var sensitiveHostRoots = []string{
	"/", "/etc", "/root", "/proc", "/sys", "/boot",
	"/usr", "/bin", "/sbin", "/lib", "/lib64", "/dev", "/var/run",
}

func isSensitiveHostPath(p string) bool {
	if isDockerSock(p) {
		return false // covered by AEGIS-COMPOSE-004
	}
	if !strings.HasPrefix(p, "/") {
		return false // named volumes and relative paths are out of scope
	}
	for _, root := range sensitiveHostRoots {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}

func (sensitiveHostMount) Check(r ir.Resource) []ir.Finding {
	rule := sensitiveHostMount{}
	vols, _, present, known := getList(r, "volumes")
	if !present || !known {
		return nil
	}
	var out []ir.Finding
	for _, v := range vols {
		s, ok := v.AsString()
		if !ok || !isSensitiveHostPath(s) {
			continue
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "volumes", v.Span, "mounts "+s,
			"dedicated data directory, read-only where possible",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-COMPOSE-006: secret in environment (high)
// ---------------------------------------------------------------------------

type composeEnvSecrets struct{}

func (composeEnvSecrets) ID() string { return "AEGIS-COMPOSE-006" }
func (composeEnvSecrets) Title() string {
	return "Secret in service environment"
}
func (composeEnvSecrets) Description() string {
	return "Literal secrets in the compose file are committed to " +
		"version control and visible to anyone who can read the file " +
		"or inspect the service. Reference secrets from a secrets " +
		"manager or an env_file outside version control."
}
func (composeEnvSecrets) Severity() ir.Severity         { return ir.SeverityHigh }
func (composeEnvSecrets) AppliesTo(resType string) bool { return appliesToCompose(resType) }

func (composeEnvSecrets) Check(r ir.Resource) []ir.Finding {
	rule := composeEnvSecrets{}
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
			r, "environment", nv.Span,
			fmt.Sprintf("%s=[REDACTED]", name),
			"secret from a manager or env_file outside version control",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-COMPOSE-007: service runs as root (medium)
// ---------------------------------------------------------------------------

type composeRootUser struct{}

func (composeRootUser) ID() string { return "AEGIS-COMPOSE-007" }
func (composeRootUser) Title() string {
	return "Service runs as root"
}
func (composeRootUser) Description() string {
	return "Without a user: directive the service runs as root; a " +
		"container breakout then yields host root. Run as a non-root " +
		"UID/GID."
}
func (composeRootUser) Severity() ir.Severity         { return ir.SeverityMedium }
func (composeRootUser) AppliesTo(resType string) bool { return appliesToCompose(resType) }

func (composeRootUser) Check(r ir.Resource) []ir.Finding {
	rule := composeRootUser{}
	user, uspan, present, known := getString(r, "user")
	if present && !known {
		return nil
	}
	if !present || strings.TrimSpace(user) == "" {
		return []ir.Finding{finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "user", r.Span, "no user directive (defaults to root)",
			"user: \"<uid>\" (non-root)",
		)}
	}
	u := strings.ToLower(strings.TrimSpace(user))
	// Strip group suffix: "uid:gid".
	if i := strings.Index(u, ":"); i >= 0 {
		u = u[:i]
	}
	if u == "root" || u == "0" {
		return []ir.Finding{finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "user", uspan, user,
			"user: \"<uid>\" (non-root)",
		)}
	}
	if n, err := strconv.Atoi(u); err == nil && n == 0 {
		return []ir.Finding{finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "user", uspan, user,
			"user: \"<uid>\" (non-root)",
		)}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-COMPOSE-008: image uses :latest (medium)
// ---------------------------------------------------------------------------

type composeLatestTag struct{}

func (composeLatestTag) ID() string { return "AEGIS-COMPOSE-008" }
func (composeLatestTag) Title() string {
	return "Service image uses :latest tag"
}
func (composeLatestTag) Description() string {
	return "Pinning :latest (or omitting the tag) makes deploys " +
		"non-reproducible and can silently pull a new, vulnerable " +
		"image. Pin an explicit version tag or digest."
}
func (composeLatestTag) Severity() ir.Severity         { return ir.SeverityMedium }
func (composeLatestTag) AppliesTo(resType string) bool { return appliesToCompose(resType) }

func (composeLatestTag) Check(r ir.Resource) []ir.Finding {
	rule := composeLatestTag{}
	img, ispan, present, known := getString(r, "image")
	if !present || !known || strings.TrimSpace(img) == "" {
		return nil
	}
	img = strings.TrimSpace(img)
	if strings.Contains(img, "@sha256:") {
		return nil
	}
	tag := ""
	// Tag is the suffix after the last ':' past the last '/'.
	rest := img
	if i := strings.Index(rest, "@"); i >= 0 {
		rest = rest[:i]
	}
	slash := strings.LastIndex(rest, "/")
	colon := strings.LastIndex(rest, ":")
	if colon > slash {
		tag = rest[colon+1:]
	}
	if tag == "" || strings.EqualFold(tag, "latest") {
		actual := "tag :latest"
		if tag == "" {
			actual = "no tag (implicit :latest)"
		}
		return []ir.Finding{finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "image", ispan, img+" ("+actual+")",
			"pinned version tag (e.g. nginx:1.25.3) or digest",
		)}
	}
	return nil
}
