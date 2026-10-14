package k8s

import (
	"strings"
	"testing"

	"aegis/internal/adapter/manifests"
	"aegis/internal/ir"
)

func parseK8s(t *testing.T, src string) []ir.Resource {
	t.Helper()
	rs, diags, err := manifests.Adapter{}.Parse("test.yaml", []byte(src))
	if err != nil {
		t.Fatalf("parse hard error: %v", err)
	}
	for _, d := range diags {
		t.Fatalf("unexpected diagnostic: %+v", d)
	}
	return rs
}

func runAll(rs []ir.Resource) map[string][]ir.Finding {
	out := map[string][]ir.Finding{}
	for _, rule := range Rules() {
		for _, r := range rs {
			if !rule.AppliesTo(r.Type) {
				continue
			}
			if fs := rule.Check(r); len(fs) > 0 {
				out[rule.ID()] = append(out[rule.ID()], fs...)
			}
		}
	}
	return out
}

const privilegedDeploy = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.25
        securityContext:
          privileged: true
          runAsNonRoot: false
      - name: sidecar
        image: busybox
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false
`

func TestPrivilegedFires(t *testing.T) {
	fired := runAll(parseK8s(t, privilegedDeploy))
	fs := fired["AEGIS-K8S-001"]
	if len(fs) != 1 {
		t.Fatalf("001 fired %d times, want 1: %v", len(fs), fired)
	}
	if !strings.Contains(fs[0].Evidence.Actual, `"app"`) {
		t.Errorf("evidence should name the container: %q", fs[0].Evidence.Actual)
	}
	if fs[0].Severity != ir.SeverityCritical {
		t.Errorf("severity = %s, want critical", fs[0].Severity)
	}
	// runAsNonRoot: false on app -> 002 fires once.
	if len(fired["AEGIS-K8S-002"]) != 1 {
		t.Errorf("002 fired %d times, want 1", len(fired["AEGIS-K8S-002"]))
	}
	// allowPrivilegeEscalation: false on sidecar, absent on app -> 003 silent.
	if len(fired["AEGIS-K8S-003"]) != 0 {
		t.Errorf("003 should not fire: %v", fired["AEGIS-K8S-003"])
	}
}

func TestCompliantContainerQuiet(t *testing.T) {
	src := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: ok
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
      - name: app
        image: nginx:1.25.3@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        resources:
          limits: {cpu: "500m", memory: "256Mi"}
        livenessProbe: {httpGet: {path: /, port: 80}}
        readinessProbe: {httpGet: {path: /, port: 80}}
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          seccompProfile: {type: RuntimeDefault}
          capabilities: {drop: [ALL]}
`
	fired := runAll(parseK8s(t, src))
	for id, fs := range fired {
		t.Errorf("rule %s fired on compliant container: %v", id, fs)
	}
}

// TestNoSecurityContextQuiet: a pod with no securityContext anywhere
// fires the no-securityContext rule (027) plus the absent-fires
// hardening rules (028 read-only rootfs, 029 seccomp, 030 drop-ALL,
// 032 image digest), and nothing else. The absent-fires rules are
// the documented exception to the missing-configuration silence:
// a wholly absent securityContext genuinely means no read-only
// rootfs, no seccomp profile, and no dropped capabilities, and the
// image genuinely has no digest pin.
func TestNoSecurityContextQuiet(t *testing.T) {
	src := `apiVersion: v1
kind: Pod
metadata:
  name: plain
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    resources:
      limits: {cpu: "500m", memory: "256Mi"}
    livenessProbe: {httpGet: {path: /, port: 80}}
    readinessProbe: {httpGet: {path: /, port: 80}}
`
	fired := runAll(parseK8s(t, src))
	want := map[string]int{
		"AEGIS-K8S-027": 1,
		"AEGIS-K8S-028": 1,
		"AEGIS-K8S-029": 1,
		"AEGIS-K8S-030": 1,
		"AEGIS-K8S-032": 1,
	}
	for id, fs := range fired {
		if want[id] == 0 {
			t.Errorf("rule %s fired with no securityContext: %v", id, fs)
		}
		if len(fs) != want[id] {
			t.Errorf("rule %s fired %d times, want %d", id, len(fs), want[id])
		}
	}
	for id, n := range want {
		if len(fired[id]) != n {
			t.Errorf("rule %s fired %d times, want %d", id, len(fired[id]), n)
		}
	}
}

func TestRunAsUserZero(t *testing.T) {
	src := `apiVersion: v1
kind: Pod
metadata:
  name: rooty
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      runAsUser: 0
`
	fired := runAll(parseK8s(t, src))
	if len(fired["AEGIS-K8S-002"]) != 1 {
		t.Errorf("002 should fire on runAsUser: 0, got %v", fired)
	}
}

func TestAllowPrivilegeEscalation(t *testing.T) {
	src := `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: agent
spec:
  template:
    spec:
      containers:
      - name: agent
        image: agent:1
        securityContext:
          allowPrivilegeEscalation: true
`
	fired := runAll(parseK8s(t, src))
	fs := fired["AEGIS-K8S-003"]
	if len(fs) != 1 {
		t.Fatalf("003 fired %d times, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Errorf("severity = %s, want high", fs[0].Severity)
	}
}

func TestInitContainers(t *testing.T) {
	src := `apiVersion: batch/v1
kind: Job
metadata:
  name: setup
spec:
  template:
    spec:
      initContainers:
      - name: init
        image: busybox
        securityContext:
          privileged: true
      containers:
      - name: main
        image: nginx
`
	fired := runAll(parseK8s(t, src))
	fs := fired["AEGIS-K8S-001"]
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence.Actual, `"init"`) {
		t.Errorf("001 should fire on privileged initContainer: %v", fs)
	}
}

func TestCronJobShape(t *testing.T) {
	src := `apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: job
            image: worker:1
            securityContext:
              privileged: true
`
	fired := runAll(parseK8s(t, src))
	if len(fired["AEGIS-K8S-001"]) != 1 {
		t.Errorf("001 should fire through CronJob nesting: %v", fired)
	}
}

func TestAppliesTo(t *testing.T) {
	k8sTypes := []string{
		"k8s_Deployment", "k8s_Pod", "k8s_Service", "k8s_Ingress",
		"k8s_Role", "k8s_ClusterRole", "k8s_RoleBinding",
		"k8s_ClusterRoleBinding", "k8s_ConfigMap",
	}
	for _, rule := range Rules() {
		hit := false
		for _, kt := range k8sTypes {
			if rule.AppliesTo(kt) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("%s should apply to at least one k8s type", rule.ID())
		}
		if rule.AppliesTo("aws_s3_bucket") || rule.AppliesTo("aws_iam_role") {
			t.Errorf("%s should not apply to AWS types", rule.ID())
		}
	}
}

func TestRuleIDs(t *testing.T) {
	rules := Rules()
	if len(rules) != 32 {
		t.Fatalf("got %d rules, want 32", len(rules))
	}
	for i, rule := range rules {
		want := "AEGIS-K8S-" + zeroPad3(i+1)
		if rule.ID() != want {
			t.Errorf("rules[%d].ID() = %s, want %s", i, rule.ID(), want)
		}
	}
}

func zeroPad3(n int) string {
	s := ""
	for v := n; v > 0; v /= 10 {
		s = string(rune('0'+v%10)) + s
	}
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

func TestNoPanicSweep(t *testing.T) {
	// Degenerate shapes must never panic a rule.
	shapes := []ir.Resource{
		{Type: "k8s_Deployment", Name: "x", Attributes: map[string]ir.Value{}},
		{Type: "k8s_Pod", Name: "x", Attributes: map[string]ir.Value{
			"spec": {Raw: "not-a-map", Known: true},
		}},
		{Type: "k8s_Deployment", Name: "x", Attributes: map[string]ir.Value{
			"spec": {Raw: map[string]ir.Value{
				"template": {Raw: map[string]ir.Value{
					"spec": {Raw: map[string]ir.Value{
						"containers": {Raw: []ir.Value{
							{Raw: "not-a-map", Known: true},
							{Raw: map[string]ir.Value{
								"name":            {Raw: "c", Known: true},
								"securityContext": ir.UnknownValue(ir.Span{}),
							}, Known: true},
						}, Known: true},
					}, Known: true},
				}, Known: true},
			}, Known: true},
		}},
	}
	for _, rule := range Rules() {
		for _, r := range shapes {
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						t.Errorf("rule %s panicked: %v", rule.ID(), rec)
					}
				}()
				_ = rule.Check(r)
			}()
		}
	}
}
