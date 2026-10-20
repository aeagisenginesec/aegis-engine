// Package compose implements ir.Adapter for Docker Compose files.
//
// Each service under top-level `services:` becomes one ir.Resource of type
// "compose_service" named after the service. Attributes:
//   - image: image reference (absent when none)
//   - privileged: bool
//   - cap_add: []Value of capability strings
//   - network_mode: string (absent when none)
//   - pid: string (absent when none)
//   - ipc: string (absent when none)
//   - user: string (absent when none)
//   - ports: []Value of published port strings
//   - volumes: []Value of host-side source paths for bind/volume mounts
//   - env_secrets: []Value of {name, span} maps for environment variables
//     that look like secrets with literal values (values redacted)
//
// Safety: malformed YAML yields a diagnostic, never a panic. Unknown
// service keys yield warning diagnostics, never silent drops.
package compose

import (
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"aegis/internal/ir"
)

// Adapter parses Docker Compose files into the canonical IR.
type Adapter struct{}

// Compile-time check that Adapter satisfies ir.Adapter.
var _ ir.Adapter = Adapter{}

// New constructs the adapter.
func New() *Adapter { return &Adapter{} }

// Name identifies the adapter.
func (Adapter) Name() string { return "compose" }

// Handles reports whether this adapter parses the given path.
func (Adapter) Handles(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
		return true
	}
	if strings.HasPrefix(base, "docker-compose.") &&
		(strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) {
		return true
	}
	return strings.HasSuffix(base, ".compose.yml") || strings.HasSuffix(base, ".compose.yaml")
}

// Parse converts a Compose file into one ir.Resource per service.
func (Adapter) Parse(path string, src []byte) ([]ir.Resource, []ir.Diagnostic, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, []ir.Diagnostic{{
			Level:   "error",
			Message: "invalid YAML: " + err.Error(),
			Span:    ir.Span{File: path, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1},
		}}, nil
	}
	root := doc.Content
	if len(root) == 0 || root[0].Kind != yaml.MappingNode {
		return nil, []ir.Diagnostic{{
			Level:   "warning",
			Message: "compose file has no top-level mapping",
			Span:    ir.Span{File: path, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1},
		}}, nil
	}
	services := mappingGet(root[0], "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil, []ir.Diagnostic{{
			Level:   "warning",
			Message: "compose file has no services",
			Span:    ir.Span{File: path, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1},
		}}, nil
	}

	var out []ir.Resource
	var diags []ir.Diagnostic
	for i := 0; i+1 < len(services.Content); i += 2 {
		name := nodeString(services.Content[i])
		svc := services.Content[i+1]
		if name == "" || svc.Kind != yaml.MappingNode {
			// A service entry that is not a mapping (e.g. `web:
			// justastring`, or an empty key) cannot become a
			// resource — but dropping it silently looks exactly
			// like a clean service. Warn, never vanish it.
			label := name
			if label == "" {
				label = "(empty name)"
			}
			diags = append(diags, ir.Diagnostic{
				Level:   "warning",
				Message: "compose: service " + label + " is not a mapping; skipped",
				Span:    ir.Span{File: path, StartLine: svc.Line, StartCol: svc.Column},
			})
			continue
		}
		r, sdiags := parseService(path, name, svc)
		out = append(out, r)
		diags = append(diags, sdiags...)
	}
	return out, diags, nil
}

// parseService converts one service mapping into a compose_service resource.
// Unknown service keys produce warning diagnostics: an ignored key is
// otherwise indistinguishable from a typo'd security setting
// (e.g. `priviliged: true` silently dropping the privileged flag).
// Keys in the Compose service spec (and x-* extension keys) are accepted
// silently; anything else is reported, never dropped quietly.
func parseService(path, name string, svc *yaml.Node) (ir.Resource, []ir.Diagnostic) {
	span := ir.Span{File: path, StartLine: svc.Line, StartCol: 1, EndLine: svc.Line, EndCol: 1}
	attrs := map[string]ir.Value{}
	var diags []ir.Diagnostic
	for i := 0; i+1 < len(svc.Content); i += 2 {
		k := nodeString(svc.Content[i])
		if k == "" || knownComposeServiceKey(k) {
			continue
		}
		diags = append(diags, ir.Diagnostic{
			Level:   "warning",
			Message: "compose: unknown service key " + k + " for service " + name + "; ignored",
			Span:    ir.Span{File: path, StartLine: svc.Content[i].Line, StartCol: svc.Content[i].Column},
		})
	}

	if img := mappingScalar(svc, "image"); img != "" {
		attrs["image"] = ir.Value{Raw: img, Known: true, Span: span}
	}
	attrs["privileged"] = boolAttr(svc, "privileged", span)
	if caps := mappingSeqStrings(svc, "cap_add"); caps != nil {
		attrs["cap_add"] = listAttr(caps, span)
	}
	if nm := mappingScalar(svc, "network_mode"); nm != "" {
		attrs["network_mode"] = ir.Value{Raw: nm, Known: true, Span: span}
	}
	if pid := mappingScalar(svc, "pid"); pid != "" {
		attrs["pid"] = ir.Value{Raw: pid, Known: true, Span: span}
	}
	if ipc := mappingScalar(svc, "ipc"); ipc != "" {
		attrs["ipc"] = ir.Value{Raw: ipc, Known: true, Span: span}
	}
	if user := mappingScalar(svc, "user"); user != "" {
		attrs["user"] = ir.Value{Raw: user, Known: true, Span: span}
	}
	if ports := servicePorts(svc); ports != nil {
		attrs["ports"] = listAttr(ports, span)
	}
	if vols := serviceVolumes(svc); vols != nil {
		attrs["volumes"] = listAttr(vols, span)
	}
	if secrets := serviceEnvSecrets(svc, span); secrets != nil {
		attrs["env_secrets"] = ir.Value{Raw: secrets, Known: true, Span: span}
	}

	return ir.Resource{
		Type:       "compose_service",
		Name:       name,
		Provider:   "docker",
		Attributes: attrs,
		Span:       span,
	}, diags
}

// knownComposeServiceKey reports whether k is a service key from the
// Compose specification (or an x-* extension key). The list is
// deliberately generous: an unlisted-but-valid key costs only a warning,
// while a typo'd security key must never vanish silently.
func knownComposeServiceKey(k string) bool {
	if strings.HasPrefix(k, "x-") {
		return true
	}
	switch k {
	case "anchor", "annotations", "build", "blkio_config", "cap_add",
		"cap_drop", "cgroup", "cgroup_parent", "command", "configs",
		"container_name", "cpu_count", "cpu_percent", "cpu_shares",
		"cpu_period", "cpu_quota", "cpu_rt_period", "cpu_rt_runtime",
		"cpus", "cpuset", "credential_spec", "depends_on", "deploy",
		"develop", "device_cgroup_rules", "devices", "dns", "dns_opt",
		"dns_search", "domainname", "entrypoint", "env_file",
		"environment", "expose", "extends", "external_links",
		"extra_hosts", "group_add", "healthcheck", "hostname", "image",
		"init", "ipc", "isolation", "labels", "links", "logging",
		"mac_address", "mem_limit", "mem_reservation", "mem_swappiness",
		"memswap_limit", "name", "network_mode", "networks",
		"oom_kill_disable", "oom_score_adj", "pid", "pids_limit",
		"platform", "ports", "privileged", "profiles", "pull_policy",
		"read_only", "restart", "runtime", "scale", "secrets",
		"security_opt", "shm_size", "stdin_open", "stop_grace_period",
		"stop_signal", "sysctls", "tmpfs", "tty", "ulimits", "user",
		"userns_mode", "volumes", "volumes_from", "working_dir":
		return true
	}
	return false
}

// servicePorts returns published port specs as strings.
func servicePorts(svc *yaml.Node) []string {
	n := mappingGet(svc, "ports")
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, item := range n.Content {
		if s := nodeString(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// serviceVolumes returns host-side source paths of mounts.
func serviceVolumes(svc *yaml.Node) []string {
	n := mappingGet(svc, "volumes")
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, item := range n.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			// Short syntax: [host:]container[:options]. Named volumes
			// have no slash in the source; keep them anyway (rules
			// only match absolute host paths).
			src := nodeString(item)
			if i := strings.Index(src, ":"); i >= 0 {
				src = src[:i]
			}
			if src != "" {
				out = append(out, src)
			}
		case yaml.MappingNode:
			if src := mappingScalar(item, "source"); src != "" {
				out = append(out, src)
			}
		}
	}
	return out
}

// serviceEnvSecrets extracts secret-looking env vars with literal values.
func serviceEnvSecrets(svc *yaml.Node, span ir.Span) []ir.Value {
	n := mappingGet(svc, "environment")
	if n == nil {
		return nil
	}
	var out []ir.Value
	add := func(name, val string) {
		if !isSecretName(name) || !isLiteralValue(val) || strings.TrimSpace(val) == "" {
			return
		}
		out = append(out, ir.Value{
			Raw: map[string]ir.Value{
				"name": {Raw: name, Known: true, Span: span},
			},
			Known: true,
			Span:  span,
		})
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			add(nodeString(n.Content[i]), nodeString(n.Content[i+1]))
		}
	case yaml.SequenceNode:
		for _, item := range n.Content {
			s := nodeString(item)
			name, val := s, ""
			if i := strings.Index(s, "="); i >= 0 {
				name, val = s[:i], s[i+1:]
			}
			add(strings.TrimSpace(name), val)
		}
	}
	return out
}

// --- yaml.Node helpers ---

// mappingGet returns the value node for key in a mapping node.
func mappingGet(m *yaml.Node, key string) *yaml.Node {
	if m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Kind == yaml.ScalarNode && m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mappingScalar returns the scalar value for key, or "" when absent.
func mappingScalar(m *yaml.Node, key string) string {
	n := mappingGet(m, key)
	if n == nil {
		return ""
	}
	return nodeString(n)
}

// mappingSeqStrings returns sequence items as strings, or nil when absent.
func mappingSeqStrings(m *yaml.Node, key string) []string {
	n := mappingGet(m, key)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, item := range n.Content {
		if s := nodeString(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// nodeString renders a scalar node (string, int, bool, null) as text.
func nodeString(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	if n.Tag == "!!null" {
		return ""
	}
	return n.Value
}

// boolAttr reads a boolean key, defaulting to false.
func boolAttr(m *yaml.Node, key string, span ir.Span) ir.Value {
	n := mappingGet(m, key)
	b := false
	if n != nil && n.Kind == yaml.ScalarNode {
		if v, err := strconv.ParseBool(strings.TrimSpace(n.Value)); err == nil {
			b = v
		}
	}
	return ir.Value{Raw: b, Known: true, Span: span}
}

// listAttr builds a []Value string list.
func listAttr(strs []string, span ir.Span) ir.Value {
	l := make([]ir.Value, 0, len(strs))
	for _, s := range strs {
		l = append(l, ir.Value{Raw: s, Known: true, Span: span})
	}
	return ir.Value{Raw: l, Known: true, Span: span}
}

// --- secret heuristics (mirrors the dockerfile adapter) ---

var secretNameHints = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
	"PRIVATE_KEY", "PRIVATEKEY", "CREDENTIAL", "AUTH",
}

func isSecretName(name string) bool {
	up := strings.ToUpper(name)
	for _, h := range secretNameHints {
		if strings.Contains(up, h) {
			return true
		}
	}
	return false
}

func isLiteralValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	unq := strings.Trim(v, `"'`)
	return !strings.Contains(unq, "$")
}
