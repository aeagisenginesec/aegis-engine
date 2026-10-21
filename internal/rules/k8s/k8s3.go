// Package k8s — hardening rules 028..032 (read-only root filesystem
// absent-fires, seccomp absent-fires, drop-ALL absent-fires,
// NetworkPolicy coverage, image digest pinning).
//
// These five are the absent-fires counterparts of narrower explicit
// rules: 028 extends 005 (explicit readOnlyRootFilesystem: false) to
// the not-explicitly-true case including pod-level inheritance;
// 029 extends 017 (explicit seccomp Unconfined) to the no-profile
// case; 030 complements 016 (explicit capabilities.add: ALL) with
// the missing-drop-ALL case. Where both fire on the same condition
// (e.g. explicit readOnlyRootFilesystem: false fires 005 and 028),
// the findings are distinct (explicit misconfiguration vs missing
// hardening) and both are kept — the same overlap pattern the pack
// already uses for runAsNonRoot (002/004/019).
//
// Unknown-value contract (same as k8s.go): a present-but-unresolved
// value yields NO finding. Absent configuration fires only where
// the rule documents it, because the secure posture is an explicit
// setting.
package k8s

import (
	"fmt"
	"sort"
	"strings"

	"aegis/internal/ir"
)

// K8s3Rules returns Kubernetes hardening rules 028..032 in ID order.
func K8s3Rules() []ir.Rule {
	return []ir.Rule{
		readOnlyRootNotTrue{},     // AEGIS-K8S-028
		noSeccompProfile{},        // AEGIS-K8S-029
		capabilitiesDropNotAll{},  // AEGIS-K8S-030
		workloadNoNetworkPolicy{}, // AEGIS-K8S-031
		imageNoDigest{},           // AEGIS-K8S-032
	}
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-028: container without read-only root filesystem (not
// explicitly true). Container-level wins when set; otherwise the
// pod-level value applies; absent at both levels fires.
// ---------------------------------------------------------------------------

type readOnlyRootNotTrue struct{}

func (readOnlyRootNotTrue) ID() string { return "AEGIS-K8S-028" }
func (readOnlyRootNotTrue) Title() string {
	return "Container without read-only root filesystem"
}
func (readOnlyRootNotTrue) Description() string {
	return "The container's effective readOnlyRootFilesystem is not " +
		"true: either it is explicitly false, or it is unset at both " +
		"the container and pod level, leaving the root filesystem " +
		"writable at runtime and aiding persistence after compromise. " +
		"Set readOnlyRootFilesystem: true and use volumes for writable " +
		"paths. (AEGIS-K8S-005 covers the explicit-false case alone.)"
}
func (readOnlyRootNotTrue) Severity() ir.Severity         { return ir.SeverityMedium }
func (readOnlyRootNotTrue) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r readOnlyRootNotTrue) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		podSC := podSecurityContext(ps)
		for _, c := range containersOf(ps) {
			// Container-level wins when the key is present.
			if v, present := c.sc["readOnlyRootFilesystem"]; present {
				b, ok := v.AsBool()
				if !ok {
					continue // unresolved: cannot decide
				}
				if b {
					continue
				}
				out = append(out, finding(r, res, c, v,
					"securityContext.readOnlyRootFilesystem",
					fmt.Sprintf("false (container %q)", c.name),
					"readOnlyRootFilesystem: true"))
				continue
			}
			// Fall back to the pod-level value.
			if podSC != nil {
				if v, present := podSC["readOnlyRootFilesystem"]; present {
					b, ok := v.AsBool()
					if !ok {
						continue // unresolved: cannot decide
					}
					if b {
						continue
					}
					out = append(out, finding(r, res, c, v,
						"securityContext.readOnlyRootFilesystem",
						fmt.Sprintf("false (pod level, container %q)", c.name),
						"readOnlyRootFilesystem: true"))
					continue
				}
			}
			// Absent at both levels: not explicitly true.
			out = append(out, finding(r, res, c, ir.Value{},
				"securityContext.readOnlyRootFilesystem",
				fmt.Sprintf("absent (container %q)", c.name),
				"readOnlyRootFilesystem: true"))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-029: container without a seccomp profile. The effective
// profile is the container-level seccompProfile.type when set,
// otherwise the pod-level one. Absent at both levels fires: a manifest
// that sets no profile requests no seccomp filtering (the runtime
// default is no profile unless the cluster sets a default).
// ---------------------------------------------------------------------------

type noSeccompProfile struct{}

func (noSeccompProfile) ID() string { return "AEGIS-K8S-029" }
func (noSeccompProfile) Title() string {
	return "Container without seccomp profile"
}
func (noSeccompProfile) Description() string {
	return "Neither the container nor the pod sets a seccompProfile " +
		"with type RuntimeDefault or Localhost, so the container runs " +
		"without seccomp syscall filtering. Set seccompProfile.type " +
		"to RuntimeDefault. (AEGIS-K8S-017 covers the explicit " +
		"Unconfined case alone.)"
}
func (noSeccompProfile) Severity() ir.Severity         { return ir.SeverityMedium }
func (noSeccompProfile) AppliesTo(resType string) bool { return appliesTo(resType) }

// seccompTypeOf reads seccompProfile.type from one securityContext map.
// Status is "known" (type resolved), "absent" (no seccompProfile key),
// or "unknown" (present but unresolvable — cannot decide).
func seccompTypeOf(sc map[string]ir.Value) (string, ir.Value, string) {
	if sc == nil {
		return "", ir.Value{}, "absent"
	}
	spv, ok := sc["seccompProfile"]
	if !ok {
		return "", ir.Value{}, "absent"
	}
	spm, ok := spv.AsMap()
	if !ok {
		return "", ir.Value{}, "unknown"
	}
	tv, ok := spm["type"]
	if !ok {
		return "", ir.Value{}, "unknown"
	}
	t, kok := tv.AsString()
	if !kok {
		return "", ir.Value{}, "unknown"
	}
	return t, tv, "known"
}

func goodSeccompType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "runtimedefault", "localhost":
		return true
	}
	return false
}

func (r noSeccompProfile) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		podSC := podSecurityContext(ps)
		for _, c := range containersOf(ps) {
			ct, cv, cs := seccompTypeOf(c.sc)
			switch cs {
			case "unknown":
				continue // cannot decide
			case "known":
				if goodSeccompType(ct) {
					continue
				}
				out = append(out, finding(r, res, c, cv,
					"securityContext.seccompProfile.type",
					fmt.Sprintf("%s (container %q)", ct, c.name),
					"type: RuntimeDefault"))
				continue
			}
			// Container level absent: fall back to pod level.
			pt, pv, pstatus := seccompTypeOf(podSC)
			switch pstatus {
			case "unknown":
				continue // cannot decide
			case "known":
				if goodSeccompType(pt) {
					continue
				}
				out = append(out, finding(r, res, c, pv,
					"securityContext.seccompProfile.type",
					fmt.Sprintf("%s (pod level, container %q)", pt, c.name),
					"type: RuntimeDefault"))
			case "absent":
				out = append(out, finding(r, res, c, ir.Value{},
					"securityContext.seccompProfile.type",
					fmt.Sprintf("absent (container %q)", c.name),
					"type: RuntimeDefault"))
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-030: container does not drop ALL capabilities. Fires when
// securityContext.capabilities.drop does not include ALL — including
// absent capabilities, absent drop, or a drop list without ALL.
// ---------------------------------------------------------------------------

type capabilitiesDropNotAll struct{}

func (capabilitiesDropNotAll) ID() string { return "AEGIS-K8S-030" }
func (capabilitiesDropNotAll) Title() string {
	return "Container does not drop ALL capabilities"
}
func (capabilitiesDropNotAll) Description() string {
	return "The container does not drop ALL Linux capabilities, so it " +
		"keeps the runtime's default capability set. Drop ALL and add " +
		"back only the specific capabilities required. " +
		"(AEGIS-K8S-016 covers the explicit capabilities.add: ALL case.)"
}
func (capabilitiesDropNotAll) Severity() ir.Severity         { return ir.SeverityMedium }
func (capabilitiesDropNotAll) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r capabilitiesDropNotAll) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		for _, c := range containersOf(ps) {
			if c.sc == nil {
				out = append(out, finding(r, res, c, ir.Value{},
					"securityContext.capabilities.drop",
					fmt.Sprintf("absent (container %q)", c.name),
					"drop: [ALL]"))
				continue
			}
			capv, ok := c.sc["capabilities"]
			if !ok {
				out = append(out, finding(r, res, c, ir.Value{},
					"securityContext.capabilities.drop",
					fmt.Sprintf("absent (container %q)", c.name),
					"drop: [ALL]"))
				continue
			}
			capm, ok := capv.AsMap()
			if !ok {
				continue // unresolved: cannot decide
			}
			dropv, ok := capm["drop"]
			if !ok {
				out = append(out, finding(r, res, c, capv,
					"securityContext.capabilities.drop",
					fmt.Sprintf("absent (container %q)", c.name),
					"drop: [ALL]"))
				continue
			}
			dropl, ok := dropv.AsList()
			if !ok {
				continue // unresolved: cannot decide
			}
			var drops []string
			unknown := false
			hasAll := false
			for _, dv := range dropl {
				s, kok := dv.AsString()
				if !kok {
					unknown = true // could be ALL: cannot decide
					break
				}
				drops = append(drops, s)
				if strings.EqualFold(strings.TrimSpace(s), "ALL") {
					hasAll = true
				}
			}
			if unknown || hasAll {
				continue
			}
			actual := fmt.Sprintf("drop: [%s] (container %q)",
				strings.Join(drops, ", "), c.name)
			out = append(out, finding(r, res, c, dropv,
				"securityContext.capabilities.drop",
				actual, "drop: [ALL]"))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-031: workload without a NetworkPolicy selecting its pods.
// Cross-resource rule: CheckAll correlates workloads with NetworkPolicy
// resources in the same namespace. One finding per uncovered workload.
// No workloads at all -> no findings.
// ---------------------------------------------------------------------------

type workloadNoNetworkPolicy struct{}

func (workloadNoNetworkPolicy) ID() string { return "AEGIS-K8S-031" }
func (workloadNoNetworkPolicy) Title() string {
	return "Workload without a NetworkPolicy"
}
func (workloadNoNetworkPolicy) Description() string {
	return "No NetworkPolicy in the workload's namespace selects its " +
		"pods, so the pods accept traffic from anywhere in the cluster. " +
		"Add a NetworkPolicy with a podSelector matching the workload's " +
		"pod labels (default-deny ingress and egress, then allow what " +
		"the workload needs)."
}
func (workloadNoNetworkPolicy) Severity() ir.Severity { return ir.SeverityMedium }

var workloadKinds = map[string]bool{
	"k8s_Deployment":  true,
	"k8s_StatefulSet": true,
	"k8s_DaemonSet":   true,
	"k8s_ReplicaSet":  true,
	"k8s_Job":         true,
	"k8s_CronJob":     true,
	"k8s_Pod":         true,
}

func (workloadNoNetworkPolicy) AppliesTo(resType string) bool {
	return workloadKinds[resType]
}

// Check is a no-op: all logic lives in CheckAll.
func (workloadNoNetworkPolicy) Check(ir.Resource) []ir.Finding { return nil }

var _ ir.CrossResourceRule = workloadNoNetworkPolicy{}

// npSelector is a parsed NetworkPolicy podSelector.
type npSelector struct {
	matchLabels      map[string]string
	matchExpressions []npExpression
}

type npExpression struct {
	key      string
	operator string
	values   []string
}

// parseNPSelector parses spec.podSelector. ok=false means unevaluable
// (unknown values or unknown operator): the policy must not be counted
// as covering anything.
func parseNPSelector(sel ir.Value) (npSelector, bool) {
	out := npSelector{matchLabels: map[string]string{}}
	sm, ok := sel.AsMap()
	if !ok {
		return out, false
	}
	if mlv, present := sm["matchLabels"]; present {
		mlm, ok := mlv.AsMap()
		if !ok {
			return out, false
		}
		for k, v := range mlm {
			s, kok := v.AsString()
			if !kok {
				return out, false
			}
			out.matchLabels[k] = s
		}
	}
	if mev, present := sm["matchExpressions"]; present {
		mel, ok := mev.AsList()
		if !ok {
			return out, false
		}
		for _, ev := range mel {
			em, ok := ev.AsMap()
			if !ok {
				return out, false
			}
			keyv, ok := em["key"]
			if !ok {
				return out, false
			}
			key, kok := keyv.AsString()
			if !kok {
				return out, false
			}
			opv, ok := em["operator"]
			if !ok {
				return out, false
			}
			op, kok := opv.AsString()
			if !kok {
				return out, false
			}
			switch op {
			case "In", "NotIn", "Exists", "DoesNotExist":
			default:
				return out, false // unknown operator: unevaluable
			}
			expr := npExpression{key: key, operator: op}
			if vv, present := em["values"]; present {
				vl, ok := vv.AsList()
				if !ok {
					return out, false
				}
				for _, item := range vl {
					s, kok := item.AsString()
					if !kok {
						return out, false
					}
					expr.values = append(expr.values, s)
				}
			}
			out.matchExpressions = append(out.matchExpressions, expr)
		}
	}
	return out, true
}

func (s npSelector) matches(labels map[string]string) bool {
	for k, v := range s.matchLabels {
		if labels[k] != v {
			return false
		}
	}
	for _, e := range s.matchExpressions {
		lv, present := labels[e.key]
		switch e.operator {
		case "In":
			if !present {
				return false
			}
			hit := false
			for _, want := range e.values {
				if lv == want {
					hit = true
					break
				}
			}
			if !hit {
				return false
			}
		case "NotIn":
			if present {
				for _, want := range e.values {
					if lv == want {
						return false
					}
				}
			}
		case "Exists":
			if !present {
				return false
			}
		case "DoesNotExist":
			if present {
				return false
			}
		}
	}
	return true
}

// resourceNamespace returns metadata.namespace, defaulting to "default".
// ok=false when the namespace is present but unresolvable.
func resourceNamespace(r ir.Resource) (string, bool) {
	mdv, ok := r.Attributes["metadata"]
	if !ok {
		return "default", true
	}
	mdm, ok := mdv.AsMap()
	if !ok {
		return "", false
	}
	nsv, ok := mdm["namespace"]
	if !ok {
		return "default", true
	}
	ns, kok := nsv.AsString()
	if !kok {
		return "", false
	}
	if ns == "" {
		return "default", true
	}
	return ns, true
}

// workloadPodLabels returns the pod-template labels for a workload, or
// metadata.labels for a bare Pod. labels==nil with ok=true means the
// workload carries no labels at all. ok=false means unresolvable.
func workloadPodLabels(r ir.Resource) (map[string]string, bool) {
	var tmplMeta map[string]ir.Value
	switch r.Type {
	case "k8s_Pod":
		mdv, ok := r.Attributes["metadata"]
		if !ok {
			return nil, true
		}
		mdm, ok := mdv.AsMap()
		if !ok {
			return nil, false
		}
		tmplMeta = mdm
	case "k8s_CronJob":
		spec, ok := r.Attributes["spec"].AsMap()
		if !ok {
			return nil, false
		}
		jt, ok := spec["jobTemplate"].AsMap()
		if !ok {
			return nil, false
		}
		jts, ok := jt["spec"].AsMap()
		if !ok {
			return nil, false
		}
		tmpl, ok := jts["template"].AsMap()
		if !ok {
			return nil, false
		}
		md, ok := tmpl["metadata"].AsMap()
		if !ok {
			return nil, true // no template metadata: no labels
		}
		tmplMeta = md
	default:
		spec, ok := r.Attributes["spec"].AsMap()
		if !ok {
			return nil, false
		}
		tmpl, ok := spec["template"].AsMap()
		if !ok {
			return nil, false
		}
		md, ok := tmpl["metadata"].AsMap()
		if !ok {
			return nil, true // no template metadata: no labels
		}
		tmplMeta = md
	}
	lv, ok := tmplMeta["labels"]
	if !ok {
		return nil, true // no labels key: no labels
	}
	lm, ok := lv.AsMap()
	if !ok {
		return nil, false
	}
	out := map[string]string{}
	for k, v := range lm {
		s, kok := v.AsString()
		if !kok {
			return nil, false
		}
		out[k] = s
	}
	return out, true
}

type npPolicy struct {
	namespace string
	selector  npSelector
	evaluable bool
}

func (s workloadNoNetworkPolicy) CheckAll(resources []ir.Resource) []ir.Finding {
	// Collect NetworkPolicies by namespace.
	policiesByNS := map[string][]npPolicy{}
	for _, r := range resources {
		if r.Type != "k8s_NetworkPolicy" {
			continue
		}
		ns, ok := resourceNamespace(r)
		if !ok {
			continue // unresolvable namespace: cannot use this policy
		}
		pol := npPolicy{namespace: ns, evaluable: true}
		spec, ok := r.Attributes["spec"].AsMap()
		if !ok {
			pol.evaluable = false
			policiesByNS[ns] = append(policiesByNS[ns], pol)
			continue
		}
		if selv, present := spec["podSelector"]; present {
			sel, ok := parseNPSelector(selv)
			if !ok {
				pol.evaluable = false
			} else {
				pol.selector = sel
			}
		}
		// Absent podSelector selects all pods: empty selector.
		policiesByNS[ns] = append(policiesByNS[ns], pol)
	}

	// Collect workloads.
	type workload struct {
		res    ir.Resource
		ns     string
		labels map[string]string
	}
	var workloads []workload
	for _, r := range resources {
		if !workloadKinds[r.Type] {
			continue
		}
		ns, ok := resourceNamespace(r)
		if !ok {
			continue // unresolvable namespace: cannot decide
		}
		labels, ok := workloadPodLabels(r)
		if !ok {
			continue // unresolvable labels: cannot decide
		}
		workloads = append(workloads, workload{res: r, ns: ns, labels: labels})
	}
	if len(workloads) == 0 {
		return nil // no workloads at all: no findings
	}

	var out []ir.Finding
	for _, w := range workloads {
		policies := policiesByNS[w.ns]
		covered := false
		unevaluable := false
		for _, pol := range policies {
			if !pol.evaluable {
				unevaluable = true // cannot prove absence of coverage
				continue
			}
			if pol.selector.matches(w.labels) {
				covered = true
				break
			}
		}
		if covered || unevaluable {
			continue
		}
		labelDesc := "no labels"
		if len(w.labels) > 0 {
			var parts []string
			for k, v := range w.labels {
				parts = append(parts, k+"="+v)
			}
			sort.Strings(parts) // determinism: map iteration order is random
			labelDesc = strings.Join(parts, ", ")
		}
		out = append(out, ir.Finding{
			RuleID:      s.ID(),
			Title:       s.Title(),
			Description: s.Description(),
			Severity:    s.Severity(),
			Resource:    w.res.Address(),
			Evidence: ir.Evidence{
				Attribute: "metadata.labels",
				Span:      w.res.Span,
				Actual: fmt.Sprintf("no NetworkPolicy selects pods (namespace %q, labels %s)",
					w.ns, labelDesc),
				Expected: "NetworkPolicy with podSelector matching this workload's pods",
			},
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-032: container image without a digest pin. Fires when the
// image reference has no @algorithm:digest suffix. An @tag suffix
// (e.g. image@latest) is not a digest and still fires.
// ---------------------------------------------------------------------------

type imageNoDigest struct{}

func (imageNoDigest) ID() string    { return "AEGIS-K8S-032" }
func (imageNoDigest) Title() string { return "Container image without digest pin" }
func (imageNoDigest) Description() string {
	return "A container image without an @digest pin (e.g. " +
		"image@sha256:...) can change under its tag: the tag may be " +
		"moved to a different image. Pin images by digest for " +
		"reproducible, verifiable deployments."
}
func (imageNoDigest) Severity() ir.Severity         { return ir.SeverityMedium }
func (imageNoDigest) AppliesTo(resType string) bool { return appliesTo(resType) }

// hasDigestPin reports whether an image reference carries an
// @algorithm:digest suffix.
func hasDigestPin(img string) bool {
	at := strings.LastIndex(img, "@")
	if at < 0 {
		return false
	}
	rest := img[at+1:]
	colon := strings.Index(rest, ":")
	if colon <= 0 || colon == len(rest)-1 {
		return false
	}
	return true
}

func (r imageNoDigest) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		for _, c := range containersOf(ps) {
			cm := containerAttrMap(c, res)
			if cm == nil {
				continue
			}
			iv, ok := cm["image"]
			if !ok {
				continue
			}
			img, kok := iv.AsString()
			if !kok {
				continue
			}
			if hasDigestPin(img) {
				continue
			}
			out = append(out, finding(r, res, c, iv, "image",
				fmt.Sprintf("%q (container %q)", img, c.name),
				"pin image by digest (image@sha256:...)"))
		}
	}
	return out
}
