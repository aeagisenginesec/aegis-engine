// Package k8s — pod security and RBAC hardening rules (AEGIS-K8S-004..025).
//
// Extends the starter pack with pod security contexts, host namespaces,
// resource limits, image hygiene, probes, capabilities, seccomp, service
// exposure, ingress TLS, RBAC wildcards, cluster-admin bindings, and
// ConfigMap secret hygiene.
//
// Unknown-value contract (same as k8s.go): a present-but-unresolved value
// yields NO finding. Explicit misconfigurations are reported; absent
// securityContext sub-fields stay silent except where the rule documents
// otherwise (resource limits, probes, ingress TLS, automount).
package k8s

import (
	"fmt"
	"strings"

	"aegis/internal/ir"
)

// K8s2Rules returns Kubernetes hardening rules 004..025 in ID order.
func K8s2Rules() []ir.Rule {
	return []ir.Rule{
		podRunAsNonRootFalse{},  // AEGIS-K8S-004
		readOnlyRootFalse{},     // AEGIS-K8S-005
		noResourceLimits{},      // AEGIS-K8S-006
		hostNetwork(),           // AEGIS-K8S-007
		hostPID(),               // AEGIS-K8S-008
		hostIPC(),               // AEGIS-K8S-009
		saTokenAutomount{},      // AEGIS-K8S-010
		hostPathVolume{},        // AEGIS-K8S-011
		imageLatestTag{},        // AEGIS-K8S-012
		imagePullPolicyNever{},  // AEGIS-K8S-013
		noLivenessProbe(),       // AEGIS-K8S-014
		noReadinessProbe(),      // AEGIS-K8S-015
		capabilitiesAddAll{},    // AEGIS-K8S-016
		seccompUnconfined{},     // AEGIS-K8S-017
		shareProcessNamespace{}, // AEGIS-K8S-018
		podRunAsUserRoot{},      // AEGIS-K8S-019
		serviceExposed{},        // AEGIS-K8S-020
		ingressNoTLS{},          // AEGIS-K8S-021
		rbacWildcard{},          // AEGIS-K8S-022
		bindingClusterAdmin{},   // AEGIS-K8S-023
		stdinTTY{},              // AEGIS-K8S-024
		configMapSensitive{},    // AEGIS-K8S-025
	}
}

// podSecurityContext returns the pod-level securityContext map, or nil.
func podSecurityContext(ps map[string]ir.Value) map[string]ir.Value {
	if sc, ok := ps["securityContext"].AsMap(); ok {
		return sc
	}
	return nil
}

// specMap returns the top-level spec map of a resource, or nil.
func specMap(r ir.Resource) map[string]ir.Value {
	if spec, ok := r.Attributes["spec"].AsMap(); ok {
		return spec
	}
	return nil
}

// scBool reads a known bool from a securityContext map.
func scBool(sc map[string]ir.Value, name string) (bool, ir.Value, bool) {
	if sc == nil {
		return false, ir.Value{}, false
	}
	v, ok := sc[name]
	if !ok {
		return false, ir.Value{}, false
	}
	b, kok := v.AsBool()
	return b, v, kok
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-004: pod-level securityContext with runAsNonRoot: false
// ---------------------------------------------------------------------------

type podRunAsNonRootFalse struct{}

func (podRunAsNonRootFalse) ID() string    { return "AEGIS-K8S-004" }
func (podRunAsNonRootFalse) Title() string { return "Pod securityContext explicitly allows root" }
func (podRunAsNonRootFalse) Description() string {
	return "A pod-level securityContext with runAsNonRoot: false forces " +
		"every container in the pod to run as root unless overridden. Set " +
		"runAsNonRoot: true at the pod level."
}
func (podRunAsNonRootFalse) Severity() ir.Severity         { return ir.SeverityHigh }
func (podRunAsNonRootFalse) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r podRunAsNonRootFalse) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		b, v, ok := scBool(podSecurityContext(ps), "runAsNonRoot")
		if !ok || b {
			continue
		}
		out = append(out, finding(r, res, container{span: res.Span}, v,
			"securityContext.runAsNonRoot", "false (pod level)",
			"runAsNonRoot: true"))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-005: container with readOnlyRootFilesystem: false
// ---------------------------------------------------------------------------

type readOnlyRootFalse struct{}

func (readOnlyRootFalse) ID() string    { return "AEGIS-K8S-005" }
func (readOnlyRootFalse) Title() string { return "Container with writable root filesystem" }
func (readOnlyRootFalse) Description() string {
	return "A container with readOnlyRootFilesystem: false can modify its " +
		"root filesystem at runtime, aiding persistence after compromise. " +
		"Set readOnlyRootFilesystem: true and use volumes for writable paths."
}
func (readOnlyRootFalse) Severity() ir.Severity         { return ir.SeverityMedium }
func (readOnlyRootFalse) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r readOnlyRootFalse) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		for _, c := range containersOf(ps) {
			b, v, ok := scBool(c.sc, "readOnlyRootFilesystem")
			if !ok || b {
				continue
			}
			out = append(out, finding(r, res, c, v,
				"securityContext.readOnlyRootFilesystem",
				fmt.Sprintf("false (container %q)", c.name),
				"readOnlyRootFilesystem: true"))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-006: container without resource limits
// ---------------------------------------------------------------------------

type noResourceLimits struct{}

func (noResourceLimits) ID() string    { return "AEGIS-K8S-006" }
func (noResourceLimits) Title() string { return "Container without resource limits" }
func (noResourceLimits) Description() string {
	return "A container without resources.limits for cpu and memory can " +
		"exhaust node resources (noisy neighbor / DoS). Set cpu and memory " +
		"limits on every container."
}
func (noResourceLimits) Severity() ir.Severity         { return ir.SeverityMedium }
func (noResourceLimits) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r noResourceLimits) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		for _, c := range containersOf(ps) {
			cm := containerAttrMap(c, res)
			rv, ok := cm["resources"]
			if !ok {
				out = append(out, limitFinding(r, res, c, "resources", "absent"))
				continue
			}
			rm, ok := rv.AsMap()
			if !ok {
				continue // unresolved shape: cannot decide
			}
			lv, ok := rm["limits"]
			if !ok {
				out = append(out, limitFinding(r, res, c, "resources.limits", "absent"))
				continue
			}
			lm, ok := lv.AsMap()
			if !ok {
				continue
			}
			var missing []string
			for _, k := range []string{"cpu", "memory"} {
				if _, ok := lm[k]; !ok {
					missing = append(missing, k)
				}
			}
			if len(missing) > 0 {
				out = append(out, limitFinding(r, res, c, "resources.limits",
					"missing "+strings.Join(missing, ", ")))
			}
		}
	}
	return out
}

// containerAttrMap recovers the raw container map for attribute lookup.
// containersOf keeps only name/sc/span, so this re-walks the pod spec.
func containerAttrMap(c container, res ir.Resource) map[string]ir.Value {
	for _, ps := range podSpecs(res) {
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
				if n, ok := cm["name"].AsString(); ok && n == c.name && cv.Span == c.span {
					return cm
				}
			}
		}
	}
	return nil
}

func limitFinding(rule ir.Rule, r ir.Resource, c container, attr, actual string) ir.Finding {
	return finding(rule, r, c, ir.Value{}, attr,
		fmt.Sprintf("%s (container %q)", actual, c.name),
		"resources.limits.cpu and resources.limits.memory set")
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-007/008/009: host namespaces
// ---------------------------------------------------------------------------

func hostNamespaceRule(id, title, desc, attr string, sev ir.Severity) ir.Rule {
	return &hostNS{id: id, title: title, desc: desc, attr: attr, sev: sev}
}

type hostNS struct {
	id, title, desc, attr string
	sev                   ir.Severity
}

func (h *hostNS) ID() string          { return h.id }
func (h *hostNS) Title() string       { return h.title }
func (h *hostNS) Description() string { return h.desc }
func (h *hostNS) Severity() ir.Severity {
	return h.sev
}
func (h *hostNS) AppliesTo(resType string) bool { return appliesTo(resType) }
func (h *hostNS) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		v, ok := ps[h.attr]
		if !ok {
			continue
		}
		b, kok := v.AsBool()
		if !kok || !b {
			continue
		}
		out = append(out, finding(h, res, container{span: res.Span}, v,
			"spec."+h.attr, "true", h.attr+": false or unset"))
	}
	return out
}

func hostNetwork() ir.Rule {
	return hostNamespaceRule("AEGIS-K8S-007",
		"Pod with hostNetwork enabled",
		"A pod with hostNetwork: true shares the node's network namespace, "+
			"bypassing network policies and exposing host ports. Avoid hostNetwork.",
		"hostNetwork", ir.SeverityHigh)
}

func hostPID() ir.Rule {
	return hostNamespaceRule("AEGIS-K8S-008",
		"Pod with hostPID enabled",
		"A pod with hostPID: true can see and signal host processes, "+
			"aiding container escape. Avoid hostPID.",
		"hostPID", ir.SeverityHigh)
}

func hostIPC() ir.Rule {
	return hostNamespaceRule("AEGIS-K8S-009",
		"Pod with hostIPC enabled",
		"A pod with hostIPC: true shares the host IPC namespace, letting "+
			"containers attack host shared memory. Avoid hostIPC.",
		"hostIPC", ir.SeverityHigh)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-010: service account token automounted
// ---------------------------------------------------------------------------

type saTokenAutomount struct{}

func (saTokenAutomount) ID() string    { return "AEGIS-K8S-010" }
func (saTokenAutomount) Title() string { return "Service account token automounted" }
func (saTokenAutomount) Description() string {
	return "A pod that mounts its service account token (explicitly via " +
		"automountServiceAccountToken: true, or implicitly with a custom " +
		"service account) hands every container credentials for the API " +
		"server. Set automountServiceAccountToken: false unless the pod " +
		"needs the API."
}
func (saTokenAutomount) Severity() ir.Severity         { return ir.SeverityMedium }
func (saTokenAutomount) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r saTokenAutomount) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		saName := ""
		for _, k := range []string{"serviceAccountName", "serviceAccount"} {
			if s, ok := ps[k].AsString(); ok {
				saName = s
			}
		}
		v, ok := ps["automountServiceAccountToken"]
		if ok {
			b, kok := v.AsBool()
			if !kok || !b {
				continue
			}
			out = append(out, finding(r, res, container{span: res.Span}, v,
				"spec.automountServiceAccountToken", "true",
				"automountServiceAccountToken: false"))
			continue
		}
		// Absent defaults to true: flag only when a non-default SA is used.
		if saName != "" && !strings.EqualFold(saName, "default") {
			out = append(out, finding(r, res, container{span: res.Span}, ir.Value{},
				"spec.automountServiceAccountToken",
				fmt.Sprintf("absent with serviceAccountName %q (defaults true)", saName),
				"automountServiceAccountToken: false"))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-011: hostPath volume
// ---------------------------------------------------------------------------

type hostPathVolume struct{}

func (hostPathVolume) ID() string    { return "AEGIS-K8S-011" }
func (hostPathVolume) Title() string { return "Pod with hostPath volume" }
func (hostPathVolume) Description() string {
	return "A hostPath volume exposes node filesystem paths to the pod, " +
		"enabling host file access or escape. Prefer PersistentVolumes " +
		"or avoid host access entirely."
}
func (hostPathVolume) Severity() ir.Severity         { return ir.SeverityHigh }
func (hostPathVolume) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r hostPathVolume) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		lv, ok := ps["volumes"].AsList()
		if !ok {
			continue
		}
		for _, vv := range lv {
			vm, ok := vv.AsMap()
			if !ok {
				continue
			}
			hp, ok := vm["hostPath"]
			if !ok {
				continue
			}
			path := ""
			if hpm, ok := hp.AsMap(); ok {
				if p, ok := hpm["path"].AsString(); ok {
					path = p
				}
			}
			actual := "hostPath volume"
			if path != "" {
				actual = fmt.Sprintf("hostPath volume (path %q)", path)
			}
			out = append(out, finding(r, res, container{span: res.Span}, hp,
				"spec.volumes[].hostPath", actual,
				"remove hostPath or use a PersistentVolume"))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-012: container image with :latest tag
// ---------------------------------------------------------------------------

type imageLatestTag struct{}

func (imageLatestTag) ID() string    { return "AEGIS-K8S-012" }
func (imageLatestTag) Title() string { return "Container image uses latest tag" }
func (imageLatestTag) Description() string {
	return "A container image without an explicit tag (implicit :latest) " +
		"or with the :latest tag is not reproducible: the image can change " +
		"under you and rollbacks are unreliable. Pin images by digest or " +
		"immutable version tag."
}
func (imageLatestTag) Severity() ir.Severity         { return ir.SeverityMedium }
func (imageLatestTag) AppliesTo(resType string) bool { return appliesTo(resType) }

// imageTag extracts the tag from an image reference; empty means :latest.
func imageTag(img string) string {
	name := img
	if i := strings.LastIndex(img, "/"); i >= 0 {
		name = img[i+1:]
	}
	if i := strings.LastIndex(name, ":"); i >= 0 {
		if strings.Contains(name[i+1:], "@") {
			return strings.SplitN(name[i+1:], "@", 2)[0]
		}
		return name[i+1:]
	}
	return ""
}

func (r imageLatestTag) Check(res ir.Resource) []ir.Finding {
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
			tag := imageTag(img)
			if tag == "" || strings.EqualFold(tag, "latest") {
				out = append(out, finding(r, res, c, iv, "image",
					fmt.Sprintf("%q (container %q)", img, c.name),
					"pin image by digest or immutable tag"))
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-013: imagePullPolicy: Never
// ---------------------------------------------------------------------------

type imagePullPolicyNever struct{}

func (imagePullPolicyNever) ID() string    { return "AEGIS-K8S-013" }
func (imagePullPolicyNever) Title() string { return "Container with imagePullPolicy Never" }
func (imagePullPolicyNever) Description() string {
	return "imagePullPolicy: Never means the kubelet never pulls the " +
		"image, silently running whatever is cached on the node — possibly " +
		"stale or tampered. Use Always (or IfNotPresent with pinned tags)."
}
func (imagePullPolicyNever) Severity() ir.Severity         { return ir.SeverityMedium }
func (imagePullPolicyNever) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r imagePullPolicyNever) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		for _, c := range containersOf(ps) {
			cm := containerAttrMap(c, res)
			if cm == nil {
				continue
			}
			iv, ok := cm["imagePullPolicy"]
			if !ok {
				continue
			}
			pol, kok := iv.AsString()
			if !kok {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(pol), "Never") {
				out = append(out, finding(r, res, c, iv, "imagePullPolicy",
					fmt.Sprintf("%q (container %q)", pol, c.name),
					"imagePullPolicy: Always"))
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-014/015: missing probes
// ---------------------------------------------------------------------------

type noProbe struct {
	id, title, desc, attr string
	sev                   ir.Severity
}

func (p *noProbe) ID() string          { return p.id }
func (p *noProbe) Title() string       { return p.title }
func (p *noProbe) Description() string { return p.desc }
func (p *noProbe) Severity() ir.Severity {
	return p.sev
}
func (p *noProbe) AppliesTo(resType string) bool { return appliesTo(resType) }
func (p *noProbe) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		for _, c := range containersOf(ps) {
			cm := containerAttrMap(c, res)
			if cm == nil {
				continue
			}
			if _, ok := cm[p.attr]; ok {
				continue
			}
			out = append(out, finding(p, res, c, ir.Value{}, p.attr,
				fmt.Sprintf("absent (container %q)", c.name),
				p.attr+" configured"))
		}
	}
	return out
}

func noLivenessProbe() ir.Rule {
	return &noProbe{id: "AEGIS-K8S-014", title: "Container without liveness probe",
		desc: "A container without a livenessProbe is never restarted " +
			"when it deadlocks, leaving a broken pod serving traffic. " +
			"Define a liveness probe.",
		attr: "livenessProbe", sev: ir.SeverityLow}
}

func noReadinessProbe() ir.Rule {
	return &noProbe{id: "AEGIS-K8S-015", title: "Container without readiness probe",
		desc: "A container without a readinessProbe receives traffic " +
			"before it is ready, causing failed requests during startup. " +
			"Define a readiness probe.",
		attr: "readinessProbe", sev: ir.SeverityLow}
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-016: capabilities add ALL
// ---------------------------------------------------------------------------

type capabilitiesAddAll struct{}

func (capabilitiesAddAll) ID() string    { return "AEGIS-K8S-016" }
func (capabilitiesAddAll) Title() string { return "Container adds ALL Linux capabilities" }
func (capabilitiesAddAll) Description() string {
	return "securityContext.capabilities.add including ALL grants the " +
		"container every Linux capability, nearly equivalent to " +
		"privileged. Add only the specific capabilities required."
}
func (capabilitiesAddAll) Severity() ir.Severity         { return ir.SeverityHigh }
func (capabilitiesAddAll) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r capabilitiesAddAll) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		for _, c := range containersOf(ps) {
			if c.sc == nil {
				continue
			}
			capv, ok := c.sc["capabilities"]
			if !ok {
				continue
			}
			capm, ok := capv.AsMap()
			if !ok {
				continue
			}
			addv, ok := capm["add"]
			if !ok {
				continue
			}
			addl, ok := addv.AsList()
			if !ok {
				continue
			}
			for _, av := range addl {
				cap, kok := av.AsString()
				if !kok {
					continue
				}
				if strings.EqualFold(strings.TrimSpace(cap), "ALL") {
					out = append(out, finding(r, res, c, av,
						"securityContext.capabilities.add",
						fmt.Sprintf("ALL (container %q)", c.name),
						"add only required capabilities"))
					break
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-017: seccompProfile Unconfined
// ---------------------------------------------------------------------------

type seccompUnconfined struct{}

func (seccompUnconfined) ID() string    { return "AEGIS-K8S-017" }
func (seccompUnconfined) Title() string { return "Seccomp profile set to Unconfined" }
func (seccompUnconfined) Description() string {
	return "securityContext.seccompProfile.type: Unconfined disables " +
		"seccomp filtering for the container or pod, removing a layer of " +
		"syscall sandboxing. Use RuntimeDefault or a custom profile."
}
func (seccompUnconfined) Severity() ir.Severity         { return ir.SeverityHigh }
func (seccompUnconfined) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r seccompUnconfined) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	checkSC := func(sc map[string]ir.Value, where string) {
		if sc == nil {
			return
		}
		spv, ok := sc["seccompProfile"]
		if !ok {
			return
		}
		spm, ok := spv.AsMap()
		if !ok {
			return
		}
		tv, ok := spm["type"]
		if !ok {
			return
		}
		t, kok := tv.AsString()
		if !kok {
			return
		}
		if strings.EqualFold(strings.TrimSpace(t), "Unconfined") {
			out = append(out, finding(r, res, container{span: res.Span}, tv,
				"securityContext.seccompProfile.type",
				fmt.Sprintf("Unconfined (%s)", where),
				"type: RuntimeDefault"))
		}
	}
	for _, ps := range podSpecs(res) {
		checkSC(podSecurityContext(ps), "pod level")
		for _, c := range containersOf(ps) {
			checkSC(c.sc, fmt.Sprintf("container %q", c.name))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-018: shareProcessNamespace
// ---------------------------------------------------------------------------

type shareProcessNamespace struct{}

func (shareProcessNamespace) ID() string    { return "AEGIS-K8S-018" }
func (shareProcessNamespace) Title() string { return "Pod shares process namespace" }
func (shareProcessNamespace) Description() string {
	return "shareProcessNamespace: true lets containers see and signal " +
		"each other's processes, weakening isolation between sidecars. " +
		"Keep it disabled unless containers must share signals."
}
func (shareProcessNamespace) Severity() ir.Severity         { return ir.SeverityMedium }
func (shareProcessNamespace) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r shareProcessNamespace) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		v, ok := ps["shareProcessNamespace"]
		if !ok {
			continue
		}
		b, kok := v.AsBool()
		if !kok || !b {
			continue
		}
		out = append(out, finding(r, res, container{span: res.Span}, v,
			"spec.shareProcessNamespace", "true",
			"shareProcessNamespace: false or unset"))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-019: pod-level runAsUser: 0
// ---------------------------------------------------------------------------

type podRunAsUserRoot struct{}

func (podRunAsUserRoot) ID() string    { return "AEGIS-K8S-019" }
func (podRunAsUserRoot) Title() string { return "Pod securityContext runs as UID 0" }
func (podRunAsUserRoot) Description() string {
	return "A pod-level securityContext with runAsUser: 0 runs every " +
		"container as root unless overridden. Set runAsUser to a non-zero " +
		"UID at the pod level."
}
func (podRunAsUserRoot) Severity() ir.Severity         { return ir.SeverityHigh }
func (podRunAsUserRoot) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r podRunAsUserRoot) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		sc := podSecurityContext(ps)
		if sc == nil {
			continue
		}
		v, ok := sc["runAsUser"]
		if !ok {
			continue
		}
		f, kok := numVal(v)
		if !kok || f != 0 {
			continue
		}
		out = append(out, finding(r, res, container{span: res.Span}, v,
			"securityContext.runAsUser", "0 (pod level)",
			"runAsUser set to a non-zero UID"))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-020: Service exposed via LoadBalancer/NodePort
// ---------------------------------------------------------------------------

type serviceExposed struct{}

func (serviceExposed) ID() string    { return "AEGIS-K8S-020" }
func (serviceExposed) Title() string { return "Service exposed externally" }
func (serviceExposed) Description() string {
	return "A Service of type LoadBalancer or NodePort exposes the " +
		"workload beyond the cluster. Prefer ClusterIP with an Ingress " +
		"that terminates TLS, and document intentional exposures."
}
func (serviceExposed) Severity() ir.Severity { return ir.SeverityMedium }

func (serviceExposed) AppliesTo(resType string) bool {
	return resType == "k8s_Service"
}

func (s serviceExposed) Check(r ir.Resource) []ir.Finding {
	spec := specMap(r)
	if spec == nil {
		return nil
	}
	tv, ok := spec["type"]
	if !ok {
		return nil // default ClusterIP
	}
	t, kok := tv.AsString()
	if !kok {
		return nil
	}
	tt := strings.ToLower(strings.TrimSpace(t))
	if tt == "loadbalancer" || tt == "nodeport" {
		return []ir.Finding{{
			RuleID:      s.ID(),
			Title:       s.Title(),
			Description: s.Description(),
			Severity:    s.Severity(),
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "spec.type",
				Span:      evidenceSpanFor(tv, container{span: r.Span}, r),
				Actual:    t,
				Expected:  "spec.type = ClusterIP",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-021: Ingress without TLS
// ---------------------------------------------------------------------------

type ingressNoTLS struct{}

func (ingressNoTLS) ID() string    { return "AEGIS-K8S-021" }
func (ingressNoTLS) Title() string { return "Ingress without TLS" }
func (ingressNoTLS) Description() string {
	return "An Ingress without a spec.tls section serves traffic over " +
		"plain HTTP. Terminate TLS at the ingress with a valid certificate."
}
func (ingressNoTLS) Severity() ir.Severity { return ir.SeverityMedium }

func (ingressNoTLS) AppliesTo(resType string) bool {
	return resType == "k8s_Ingress"
}

func (s ingressNoTLS) Check(r ir.Resource) []ir.Finding {
	spec := specMap(r)
	if spec == nil {
		return nil
	}
	tv, ok := spec["tls"]
	if !ok {
		return []ir.Finding{{
			RuleID:      s.ID(),
			Title:       s.Title(),
			Description: s.Description(),
			Severity:    s.Severity(),
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "spec.tls",
				Span:      evidenceSpanFor(ir.Value{}, container{span: r.Span}, r),
				Actual:    "absent (plain HTTP)",
				Expected:  "spec.tls with hosts and secretName",
			},
		}}
	}
	if l, ok := tv.AsList(); ok && len(l) == 0 {
		return []ir.Finding{{
			RuleID:      s.ID(),
			Title:       s.Title(),
			Description: s.Description(),
			Severity:    s.Severity(),
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "spec.tls",
				Span:      evidenceSpanFor(tv, container{span: r.Span}, r),
				Actual:    "empty tls list",
				Expected:  "spec.tls with hosts and secretName",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-022: RBAC role with wildcard verbs/resources
// ---------------------------------------------------------------------------

type rbacWildcard struct{}

func (rbacWildcard) ID() string    { return "AEGIS-K8S-022" }
func (rbacWildcard) Title() string { return "RBAC role with wildcard permissions" }
func (rbacWildcard) Description() string {
	return "A Role or ClusterRole rule with verbs [\"*\"] or resources " +
		"[\"*\"] grants unrestricted API access, equivalent to " +
		"cluster-admin for its scope. Enumerate the verbs and resources " +
		"actually needed."
}
func (rbacWildcard) Severity() ir.Severity { return ir.SeverityHigh }

func (rbacWildcard) AppliesTo(resType string) bool {
	return resType == "k8s_Role" || resType == "k8s_ClusterRole"
}

func (s rbacWildcard) Check(r ir.Resource) []ir.Finding {
	rv, ok := r.Attributes["rules"]
	if !ok {
		return nil
	}
	rl, ok := rv.AsList()
	if !ok {
		return nil
	}
	for _, item := range rl {
		rm, ok := item.AsMap()
		if !ok {
			continue
		}
		for _, attr := range []string{"verbs", "resources"} {
			lv, ok := rm[attr]
			if !ok {
				continue
			}
			l, ok := lv.AsList()
			if !ok {
				continue
			}
			for _, ev := range l {
				str, kok := ev.AsString()
				if !kok {
					continue
				}
				if strings.TrimSpace(str) == "*" {
					return []ir.Finding{{
						RuleID:      s.ID(),
						Title:       s.Title(),
						Description: s.Description(),
						Severity:    s.Severity(),
						Resource:    r.Address(),
						Evidence: ir.Evidence{
							Attribute: "rules." + attr,
							Span:      evidenceSpanFor(ev, container{span: r.Span}, r),
							Actual:    fmt.Sprintf("%s: [\"*\"]", attr),
							Expected:  "enumerate specific " + attr,
						},
					}}
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-023: binding to cluster-admin
// ---------------------------------------------------------------------------

type bindingClusterAdmin struct{}

func (bindingClusterAdmin) ID() string    { return "AEGIS-K8S-023" }
func (bindingClusterAdmin) Title() string { return "Binding grants cluster-admin" }
func (bindingClusterAdmin) Description() string {
	return "A RoleBinding or ClusterRoleBinding whose roleRef points at " +
		"cluster-admin grants full cluster control to its subjects. Bind " +
		"least-privilege roles instead and audit cluster-admin bindings."
}
func (bindingClusterAdmin) Severity() ir.Severity { return ir.SeverityCritical }

func (bindingClusterAdmin) AppliesTo(resType string) bool {
	return resType == "k8s_RoleBinding" || resType == "k8s_ClusterRoleBinding"
}

func (s bindingClusterAdmin) Check(r ir.Resource) []ir.Finding {
	rrv, ok := r.Attributes["roleRef"]
	if !ok {
		return nil
	}
	rrm, ok := rrv.AsMap()
	if !ok {
		return nil
	}
	nv, ok := rrm["name"]
	if !ok {
		return nil
	}
	name, kok := nv.AsString()
	if !kok {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(name), "cluster-admin") {
		return []ir.Finding{{
			RuleID:      s.ID(),
			Title:       s.Title(),
			Description: s.Description(),
			Severity:    s.Severity(),
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "roleRef.name",
				Span:      evidenceSpanFor(nv, container{span: r.Span}, r),
				Actual:    name,
				Expected:  "bind a least-privilege role",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-024: container with stdin and tty
// ---------------------------------------------------------------------------

type stdinTTY struct{}

func (stdinTTY) ID() string    { return "AEGIS-K8S-024" }
func (stdinTTY) Title() string { return "Container with interactive stdin/tty" }
func (stdinTTY) Description() string {
	return "A container with both stdin: true and tty: true is configured " +
		"for interactive debugging sessions, which should not ship to " +
		"production. Remove stdin/tty from workload manifests."
}
func (stdinTTY) Severity() ir.Severity         { return ir.SeverityLow }
func (stdinTTY) AppliesTo(resType string) bool { return appliesTo(resType) }

func (r stdinTTY) Check(res ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, ps := range podSpecs(res) {
		for _, c := range containersOf(ps) {
			cm := containerAttrMap(c, res)
			if cm == nil {
				continue
			}
			stdin, sok := boolAttr(cm, "stdin")
			tty, tok := boolAttr(cm, "tty")
			if sok && tok && stdin && tty {
				out = append(out, finding(r, res, c, ir.Value{}, "stdin/tty",
					fmt.Sprintf("stdin and tty true (container %q)", c.name),
					"stdin: false, tty: false or unset"))
			}
		}
	}
	return out
}

func boolAttr(m map[string]ir.Value, name string) (bool, bool) {
	v, ok := m[name]
	if !ok {
		return false, false
	}
	b, kok := v.AsBool()
	return b, kok
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-025: ConfigMap with sensitive-looking keys
// ---------------------------------------------------------------------------

type configMapSensitive struct{}

func (configMapSensitive) ID() string    { return "AEGIS-K8S-025" }
func (configMapSensitive) Title() string { return "ConfigMap holds sensitive values" }
func (configMapSensitive) Description() string {
	return "A ConfigMap with data keys like password, token or secret " +
		"stores credentials in plain text, readable by anyone with " +
		"ConfigMap read access. Move secrets to a Secret (ideally " +
		"external secrets management)."
}
func (configMapSensitive) Severity() ir.Severity { return ir.SeverityMedium }

func (configMapSensitive) AppliesTo(resType string) bool {
	return resType == "k8s_ConfigMap"
}

var sensitiveKeyParts = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"private_key", "privatekey", "client_secret", "access_key",
}

func (s configMapSensitive) Check(r ir.Resource) []ir.Finding {
	dv, ok := r.Attributes["data"]
	if !ok {
		return nil
	}
	dm, ok := dv.AsMap()
	if !ok {
		return nil
	}
	for key, val := range dm {
		lk := strings.ToLower(key)
		hit := false
		for _, part := range sensitiveKeyParts {
			if strings.Contains(lk, part) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		return []ir.Finding{{
			RuleID:      s.ID(),
			Title:       s.Title(),
			Description: s.Description(),
			Severity:    s.Severity(),
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "data." + key,
				Span:      evidenceSpanFor(val, container{span: r.Span}, r),
				Actual:    fmt.Sprintf("sensitive-looking key %q", key),
				Expected:  "store in a Secret, not a ConfigMap",
			},
		}}
	}
	return nil
}
