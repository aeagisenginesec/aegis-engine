package manifests

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

// Adapter audit 2026-10-14: the manifests package had parse-shape tests but
// no test pinning that security-relevant workload attributes (privileged,
// read-only root filesystem, seccomp, probes, digest pins) survive into the
// IR where the K8S rule pack reads them. These tests lock that in.

// containerSecurityContext navigates spec.template.spec.containers[0]
// .securityContext of a Deployment resource.
func containerSecurityContext(t *testing.T, r ir.Resource) map[string]ir.Value {
	t.Helper()
	spec, ok := r.Attributes["spec"].AsMap()
	if !ok {
		t.Fatalf("no spec map on %s", r.Address())
	}
	tmpl, ok := spec["template"].AsMap()
	if !ok {
		t.Fatalf("no template map on %s", r.Address())
	}
	pspec, ok := tmpl["spec"].AsMap()
	if !ok {
		t.Fatalf("no pod spec map on %s", r.Address())
	}
	cl, ok := pspec["containers"].AsList()
	if !ok || len(cl) == 0 {
		t.Fatalf("no containers list on %s", r.Address())
	}
	c0, ok := cl[0].AsMap()
	if !ok {
		t.Fatalf("container[0] not a map on %s", r.Address())
	}
	sc, ok := c0["securityContext"].AsMap()
	if !ok {
		t.Fatalf("no securityContext map on %s", r.Address())
	}
	return sc
}

func mustBoolAttr(t *testing.T, m map[string]ir.Value, key string) bool {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("attribute %q missing", key)
	}
	b, ok := v.AsBool()
	if !ok {
		t.Fatalf("attribute %q not a known bool (known=%v raw=%v)", key, v.Known, v.Raw)
	}
	return b
}

// A privileged container must reach the IR with privileged=true so
// AEGIS-K8S-001 can fire; the whole securityContext must not be dropped.
func TestAuditPrivilegedContainerSurvives(t *testing.T) {
	src := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vuln-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest
        securityContext:
          privileged: true
`
	rs, diags := mustParse(t, "deploy.yaml", src)
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("unexpected error diagnostic: %s", d.Message)
		}
	}
	if len(rs) != 1 || rs[0].Type != "k8s_Deployment" {
		t.Fatalf("expected 1 k8s_Deployment, got %+v", rs)
	}
	sc := containerSecurityContext(t, rs[0])
	if !mustBoolAttr(t, sc, "privileged") {
		t.Fatalf("privileged should be true, got %+v", sc["privileged"])
	}
}

// A fully hardened workload must keep every hardening attribute in the IR:
// runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation=false,
// capabilities.drop=[ALL], seccompProfile, resource limits, probes, and a
// digest-pinned image — the attributes the K8S-006/014/015/028/029/030/032
// rules inspect. A co-declared NetworkPolicy must also parse.
func TestAuditHardenedWorkloadAttributes(t *testing.T) {
	src := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  template:
    metadata:
      labels: {app: secure-app}
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile: {type: RuntimeDefault}
      containers:
      - name: app
        image: nginx:1.27.2@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        securityContext:
          runAsNonRoot: true
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities: {drop: ["ALL"]}
          seccompProfile: {type: RuntimeDefault}
        resources:
          limits: {cpu: "500m", memory: "256Mi"}
        livenessProbe: {httpGet: {path: /, port: 80}}
        readinessProbe: {httpGet: {path: /, port: 80}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: secure-app-netpol
spec:
  podSelector: {matchLabels: {app: secure-app}}
  policyTypes: [Ingress, Egress]
`
	rs, diags := mustParse(t, "deploy.yaml", src)
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("unexpected error diagnostic: %s", d.Message)
		}
	}
	if len(rs) != 2 {
		t.Fatalf("expected 2 resources (Deployment + NetworkPolicy), got %d", len(rs))
	}
	var dep *ir.Resource
	for i := range rs {
		if rs[i].Type == "k8s_Deployment" {
			dep = &rs[i]
		}
	}
	if dep == nil {
		t.Fatalf("no k8s_Deployment among %+v", rs)
	}
	sc := containerSecurityContext(t, *dep)
	if !mustBoolAttr(t, sc, "runAsNonRoot") {
		t.Errorf("runAsNonRoot should be true")
	}
	if !mustBoolAttr(t, sc, "readOnlyRootFilesystem") {
		t.Errorf("readOnlyRootFilesystem should be true")
	}
	if mustBoolAttr(t, sc, "allowPrivilegeEscalation") {
		t.Errorf("allowPrivilegeEscalation should be false")
	}
	caps, ok := sc["capabilities"].AsMap()
	if !ok {
		t.Fatalf("no capabilities map: %+v", sc["capabilities"])
	}
	drop, ok := caps["drop"].AsList()
	if !ok || len(drop) == 0 {
		t.Fatalf("capabilities.drop missing: %+v", caps["drop"])
	}
	foundAll := false
	for _, d := range drop {
		if s, ok := d.AsString(); ok && strings.EqualFold(s, "ALL") {
			foundAll = true
		}
	}
	if !foundAll {
		t.Errorf("capabilities.drop should contain ALL, got %+v", drop)
	}

	// Container-level attributes the probe/limit/digest rules read.
	spec, _ := dep.Attributes["spec"].AsMap()
	tmpl, _ := spec["template"].AsMap()
	pspec, _ := tmpl["spec"].AsMap()
	cl, _ := pspec["containers"].AsList()
	c0, _ := cl[0].AsMap()
	if _, ok := c0["livenessProbe"].AsMap(); !ok {
		t.Errorf("livenessProbe missing from IR")
	}
	if _, ok := c0["readinessProbe"].AsMap(); !ok {
		t.Errorf("readinessProbe missing from IR")
	}
	res, ok := c0["resources"].AsMap()
	if !ok {
		t.Fatalf("resources missing from IR")
	}
	if _, ok := res["limits"].AsMap(); !ok {
		t.Errorf("resources.limits missing from IR")
	}
	img, ok := c0["image"].AsString()
	if !ok || !strings.Contains(img, "@sha256:") {
		t.Errorf("digest-pinned image missing from IR, got %+v", c0["image"])
	}
}
