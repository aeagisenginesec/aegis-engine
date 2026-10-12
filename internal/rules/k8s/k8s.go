// Package k8s implements the starter Kubernetes rule pack for Aegis.
//
// The manifests adapter produces k8s_<Kind> resources carrying the whole
// manifest document as attributes. These rules navigate the pod spec at
// spec (Pod), spec.template.spec (workloads), or
// spec.jobTemplate.spec.template.spec (CronJob), inspecting containers and
// initContainers. Missing or unknown securityContext never produces a
// finding: the rules report only explicit misconfigurations.
package k8s

import (
	"fmt"
	"strings"

	"aegis/internal/ir"
)

// Rules returns every rule in the Kubernetes pack, in ID order.
func Rules() []ir.Rule {
	return []ir.Rule{
		privilegedContainer{}, // AEGIS-K8S-001
		runAsRootContainer{},  // AEGIS-K8S-002
		privilegeEscalation{}, // AEGIS-K8S-003
	}
}

// appliesTo reports whether a resource type belongs to this pack.
func appliesTo(resType string) bool { return strings.HasPrefix(resType, "k8s_") }

// container is one container or initContainer with its securityContext.
type container struct {
	name string
	sc   map[string]ir.Value // nil when absent or unresolvable
	span ir.Span
}

// podSpecs extracts pod-spec-shaped maps from a k8s resource, covering Pod,
// workload (Deployment/DaemonSet/StatefulSet/ReplicaSet/Job), and CronJob
// shapes. Unknown shapes yield nothing.
func podSpecs(r ir.Resource) []map[string]ir.Value {
	specV, ok := r.Attributes["spec"]
	if !ok {
		return nil
	}
	spec, ok := specV.AsMap()
	if !ok {
		return nil
	}
	if hasContainers(spec) {
		return []map[string]ir.Value{spec} // Pod
	}
	if tmpl, ok := spec["template"].AsMap(); ok {
		if ps, ok := tmpl["spec"].AsMap(); ok {
			return []map[string]ir.Value{ps} // workload
		}
	}
	if jt, ok := spec["jobTemplate"].AsMap(); ok { // CronJob
		if jts, ok := jt["spec"].AsMap(); ok {
			if tmpl, ok := jts["template"].AsMap(); ok {
				if ps, ok := tmpl["spec"].AsMap(); ok {
					return []map[string]ir.Value{ps}
				}
			}
		}
	}
	return nil
}

func hasContainers(m map[string]ir.Value) bool {
	_, ok1 := m["containers"]
	_, ok2 := m["initContainers"]
	return ok1 || ok2
}

// containersOf returns containers and initContainers in document order.
func containersOf(ps map[string]ir.Value) []container {
	var out []container
	for _, key := range []string{"containers", "initContainers"} {
		lv, ok := ps[key].AsList()
		if !ok {
			continue
		}
		for _, cv := range lv {
			cm, ok := cv.AsMap()
			if !ok {
				continue
			}
			c := container{span: cv.Span}
			if n, ok := cm["name"].AsString(); ok {
				c.name = n
			}
			if sc, ok := cm["securityContext"].AsMap(); ok {
				c.sc = sc
			}
			out = append(out, c)
		}
	}
	return out
}

// numVal extracts a known numeric value.
func numVal(v ir.Value) (float64, bool) {
	if !v.Known {
		return 0, false
	}
	f, ok := v.Raw.(float64)
	return f, ok
}

// evidenceSpanFor prefers the attribute span, then the container span, then
// the resource span.
func evidenceSpanFor(attr ir.Value, c container, r ir.Resource) ir.Span {
	if attr.Span.File != "" {
		return attr.Span
	}
	if c.span.File != "" {
		return c.span
	}
	return r.Span
}

func finding(rule ir.Rule, r ir.Resource, c container, attr ir.Value, attribute, actual, expected string) ir.Finding {
	return ir.Finding{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attribute,
			Span:      evidenceSpanFor(attr, c, r),
			Actual:    actual,
			Expected:  expected,
		},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-001: privileged container
// ---------------------------------------------------------------------------

type privilegedContainer struct{}

func (privilegedContainer) ID() string    { return "AEGIS-K8S-001" }
func (privilegedContainer) Title() string { return "Container running as privileged" }
func (privilegedContainer) Description() string {
	return "A privileged container has full access to the host, bypassing " +
		"almost all isolation. Privilege is almost never required for " +
		"application containers."
}
func (privilegedContainer) Severity() ir.Severity         { return ir.SeverityCritical }
func (privilegedContainer) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r privilegedContainer) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		for _, c := range containersOf(ps) {
			if c.sc == nil {
				continue
			}
			v, ok := c.sc["privileged"]
			if !ok {
				continue
			}
			b, ok := v.AsBool()
			if !ok || !b {
				continue // unknown or false: cannot decide / compliant
			}
			out = append(out, finding(r, res, c, v,
				"securityContext.privileged",
				fmt.Sprintf("true (container %q)", c.name),
				"privileged: false or unset"))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-002: container running as root
// ---------------------------------------------------------------------------

type runAsRootContainer struct{}

func (runAsRootContainer) ID() string    { return "AEGIS-K8S-002" }
func (runAsRootContainer) Title() string { return "Container running as root user" }
func (runAsRootContainer) Description() string {
	return "Containers should run as a non-root user. An explicit " +
		"runAsNonRoot: false or runAsUser: 0 keeps the container root, " +
		"magnifying the impact of a container escape."
}
func (runAsRootContainer) Severity() ir.Severity         { return ir.SeverityHigh }
func (runAsRootContainer) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r runAsRootContainer) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		for _, c := range containersOf(ps) {
			if c.sc == nil {
				continue
			}
			if v, ok := c.sc["runAsNonRoot"]; ok {
				if b, ok := v.AsBool(); ok && !b {
					out = append(out, finding(r, res, c, v,
						"securityContext.runAsNonRoot",
						fmt.Sprintf("false (container %q)", c.name),
						"runAsNonRoot: true"))
				}
			}
			if v, ok := c.sc["runAsUser"]; ok {
				if f, ok := numVal(v); ok && f == 0 {
					out = append(out, finding(r, res, c, v,
						"securityContext.runAsUser",
						fmt.Sprintf("0 (container %q)", c.name),
						"runAsUser set to a non-zero UID"))
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-003: privilege escalation allowed
// ---------------------------------------------------------------------------

type privilegeEscalation struct{}

func (privilegeEscalation) ID() string    { return "AEGIS-K8S-003" }
func (privilegeEscalation) Title() string { return "Container allows privilege escalation" }
func (privilegeEscalation) Description() string {
	return "allowPrivilegeEscalation: true lets a process gain more " +
		"privileges than its parent, typically via setuid binaries. It " +
		"should be false unless the workload genuinely needs it."
}
func (privilegeEscalation) Severity() ir.Severity         { return ir.SeverityHigh }
func (privilegeEscalation) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r privilegeEscalation) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		for _, c := range containersOf(ps) {
			if c.sc == nil {
				continue
			}
			v, ok := c.sc["allowPrivilegeEscalation"]
			if !ok {
				continue
			}
			b, ok := v.AsBool()
			if !ok || !b {
				continue
			}
			out = append(out, finding(r, res, c, v,
				"securityContext.allowPrivilegeEscalation",
				fmt.Sprintf("true (container %q)", c.name),
				"allowPrivilegeEscalation: false"))
		}
	}
	return out
}
