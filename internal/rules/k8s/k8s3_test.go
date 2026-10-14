package k8s

import (
	"testing"

	"aegis/internal/ir"
)

// runCheckAll evaluates a cross-resource rule the way the engine does.
func runCheckAll(t *testing.T, src, ruleID string) int {
	t.Helper()
	rs := parseK8s(t, src)
	n := 0
	for _, rule := range Rules() {
		if rule.ID() != ruleID {
			continue
		}
		if cr, ok := rule.(ir.CrossResourceRule); ok {
			for _, f := range cr.CheckAll(rs) {
				if f.RuleID == ruleID {
					n++
				}
			}
		}
	}
	return n
}

func mustFireAll(t *testing.T, src, ruleID string, n int) {
	t.Helper()
	if got := runCheckAll(t, src, ruleID); got != n {
		t.Fatalf("%s fired %d times via CheckAll, want %d", ruleID, got, n)
	}
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-028: read-only root filesystem not explicitly true
// ---------------------------------------------------------------------------

func TestK8S028(t *testing.T) {
	explicitFalse := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {readOnlyRootFilesystem: false}
`
	mustFire(t, explicitFalse, "AEGIS-K8S-028", 1)

	absent := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {runAsNonRoot: true}
`
	mustFire(t, absent, "AEGIS-K8S-028", 1) // unset at both levels

	noSC := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, noSC, "AEGIS-K8S-028", 1) // no securityContext at all

	podFalse := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {readOnlyRootFilesystem: false}
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, podFalse, "AEGIS-K8S-028", 1) // inherited from pod level

	podTrue := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {readOnlyRootFilesystem: true}
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, podTrue, "AEGIS-K8S-028", 0) // inherited true

	containerWins := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {readOnlyRootFilesystem: false}
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {readOnlyRootFilesystem: true}
`
	mustFire(t, containerWins, "AEGIS-K8S-028", 0) // container true overrides pod false

	containerLoses := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {readOnlyRootFilesystem: true}
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {readOnlyRootFilesystem: false}
`
	mustFire(t, containerLoses, "AEGIS-K8S-028", 1) // container false overrides pod true
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-029: no seccomp profile
// ---------------------------------------------------------------------------

func TestK8S029(t *testing.T) {
	absent := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {runAsNonRoot: true}
`
	mustFire(t, absent, "AEGIS-K8S-029", 1) // no profile anywhere

	noSC := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, noSC, "AEGIS-K8S-029", 1) // no securityContext = no profile

	unconfined := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {seccompProfile: {type: Unconfined}}
`
	mustFire(t, unconfined, "AEGIS-K8S-029", 1)

	podUnconfined := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {seccompProfile: {type: Unconfined}}
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, podUnconfined, "AEGIS-K8S-029", 1) // inherited Unconfined

	runtimeDefault := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {seccompProfile: {type: RuntimeDefault}}
`
	mustFire(t, runtimeDefault, "AEGIS-K8S-029", 0)

	localhost := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {seccompProfile: {type: Localhost, localhostRef: profiles/audit.json}}
`
	mustFire(t, localhost, "AEGIS-K8S-029", 0)

	podDefault := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {seccompProfile: {type: RuntimeDefault}}
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, podDefault, "AEGIS-K8S-029", 0) // inherited RuntimeDefault

	containerWins := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {seccompProfile: {type: Unconfined}}
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {seccompProfile: {type: RuntimeDefault}}
`
	mustFire(t, containerWins, "AEGIS-K8S-029", 0) // container RuntimeDefault wins
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-030: capabilities.drop does not include ALL
// ---------------------------------------------------------------------------

func TestK8S030(t *testing.T) {
	noCaps := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {runAsNonRoot: true}
`
	mustFire(t, noCaps, "AEGIS-K8S-030", 1) // no capabilities block

	noSC := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, noSC, "AEGIS-K8S-030", 1)

	noDrop := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {capabilities: {add: [NET_BIND_SERVICE]}}
`
	mustFire(t, noDrop, "AEGIS-K8S-030", 1) // drop key absent

	partialDrop := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {capabilities: {drop: [NET_RAW]}}
`
	mustFire(t, partialDrop, "AEGIS-K8S-030", 1) // drop without ALL

	emptyDrop := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {capabilities: {drop: []}}
`
	mustFire(t, emptyDrop, "AEGIS-K8S-030", 1)

	dropAll := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {capabilities: {drop: [ALL]}}
`
	mustFire(t, dropAll, "AEGIS-K8S-030", 0)

	dropAllPlus := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {capabilities: {drop: [ALL], add: [NET_BIND_SERVICE]}}
`
	mustFire(t, dropAllPlus, "AEGIS-K8S-030", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-031: workload without a NetworkPolicy
// ---------------------------------------------------------------------------

func TestK8S031(t *testing.T) {
	deployOnly := `apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - {name: app, image: nginx:1.25.3}
`
	mustFireAll(t, deployOnly, "AEGIS-K8S-031", 1)

	emptySelector := deployOnly + `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
`
	mustFireAll(t, emptySelector, "AEGIS-K8S-031", 0) // empty selector = all pods

	noSelector := deployOnly + `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny}
spec:
  policyTypes: [Ingress]
`
	mustFireAll(t, noSelector, "AEGIS-K8S-031", 0) // absent selector = all pods

	matchLabels := deployOnly + `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-web}
spec:
  podSelector:
    matchLabels: {app: web}
`
	mustFireAll(t, matchLabels, "AEGIS-K8S-031", 0)

	nonMatchingLabels := deployOnly + `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-other}
spec:
  podSelector:
    matchLabels: {app: other}
`
	mustFireAll(t, nonMatchingLabels, "AEGIS-K8S-031", 1)

	matchExprIn := deployOnly + `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-web}
spec:
  podSelector:
    matchExpressions:
    - {key: app, operator: In, values: [web, api]}
`
	mustFireAll(t, matchExprIn, "AEGIS-K8S-031", 0)

	matchExprNotIn := deployOnly + `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-nonprod}
spec:
  podSelector:
    matchExpressions:
    - {key: env, operator: NotIn, values: [prod]}
`
	mustFireAll(t, matchExprNotIn, "AEGIS-K8S-031", 0) // env label absent: NotIn passes

	matchExprExists := deployOnly + `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-labeled}
spec:
  podSelector:
    matchExpressions:
    - {key: app, operator: Exists}
`
	mustFireAll(t, matchExprExists, "AEGIS-K8S-031", 0)

	matchExprDoesNotExist := deployOnly + `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-unlabeled}
spec:
  podSelector:
    matchExpressions:
    - {key: team, operator: DoesNotExist}
`
	mustFireAll(t, matchExprDoesNotExist, "AEGIS-K8S-031", 0) // team absent

	otherNamespace := deployOnly + `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-web, namespace: prod}
spec:
  podSelector:
    matchLabels: {app: web}
`
	mustFireAll(t, otherNamespace, "AEGIS-K8S-031", 1) // policy in another namespace

	sameNamespace := `apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - {name: app, image: nginx:1.25.3}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-web, namespace: prod}
spec:
  podSelector:
    matchLabels: {app: web}
`
	mustFireAll(t, sameNamespace, "AEGIS-K8S-031", 0)

	policyOnly := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny}
spec:
  podSelector: {}
`
	mustFireAll(t, policyOnly, "AEGIS-K8S-031", 0) // no workloads at all

	barePod := `apiVersion: v1
kind: Pod
metadata: {name: solo, labels: {app: solo}}
spec:
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFireAll(t, barePod, "AEGIS-K8S-031", 1)

	twoWorkloadsOneCovered := deployOnly + `---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
      - {name: app, image: nginx:1.25.3}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-web}
spec:
  podSelector:
    matchLabels: {app: web}
`
	mustFireAll(t, twoWorkloadsOneCovered, "AEGIS-K8S-031", 1) // only api uncovered
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-032: image without digest pin
// ---------------------------------------------------------------------------

func TestK8S032(t *testing.T) {
	tagged := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, tagged, "AEGIS-K8S-032", 1)

	untagged := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx}
`
	mustFire(t, untagged, "AEGIS-K8S-032", 1)

	atTag := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx@latest}
`
	mustFire(t, atTag, "AEGIS-K8S-032", 1) // @tag is not a digest

	digest := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855}
`
	mustFire(t, digest, "AEGIS-K8S-032", 0)

	tagPlusDigest := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx:1.25.3@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855}
`
	mustFire(t, tagPlusDigest, "AEGIS-K8S-032", 0)

	registryDigest := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: registry:5000/team/app@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855}
`
	mustFire(t, registryDigest, "AEGIS-K8S-032", 0)
}

// ---------------------------------------------------------------------------
// Combined: the vulnerable k8s-vuln fixture shape fires all five.
// ---------------------------------------------------------------------------

func TestK8S028_032_VulnFixture(t *testing.T) {
	src := `apiVersion: apps/v1
kind: Deployment
metadata: {name: vuln-app}
spec:
  template:
    metadata: {labels: {app: vuln}}
    spec:
      hostNetwork: true
      containers:
      - name: app
        image: nginx:latest
        securityContext:
          privileged: true
          runAsUser: 0
          allowPrivilegeEscalation: true
---
apiVersion: v1
kind: Service
metadata: {name: vuln-svc}
spec:
  type: NodePort
  selector: {app: vuln}
  ports:
  - {port: 80, targetPort: 80, nodePort: 30080}
`
	for _, id := range []string{"AEGIS-K8S-028", "AEGIS-K8S-029", "AEGIS-K8S-030", "AEGIS-K8S-032"} {
		mustFire(t, src, id, 1)
	}
	mustFireAll(t, src, "AEGIS-K8S-031", 1)
}
