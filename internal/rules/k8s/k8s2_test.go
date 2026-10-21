package k8s

import (
	"testing"
)

func firedCount(t *testing.T, src, ruleID string) int {
	t.Helper()
	return len(runAll(parseK8s(t, src))[ruleID])
}

func mustFire(t *testing.T, src, ruleID string, n int) {
	t.Helper()
	if got := firedCount(t, src, ruleID); got != n {
		t.Fatalf("%s fired %d times, want %d", ruleID, got, n)
	}
}

const basePod = `apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    resources:
      limits:
        cpu: "500m"
        memory: "256Mi"
    livenessProbe:
      httpGet: {path: /, port: 80}
    readinessProbe:
      httpGet: {path: /, port: 80}
`

// ---------------------------------------------------------------------------
// AEGIS-K8S-004: pod-level runAsNonRoot: false
// ---------------------------------------------------------------------------

func TestK8S004(t *testing.T) {
	bad := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {runAsNonRoot: false}
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, bad, "AEGIS-K8S-004", 1)
	good := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, good, "AEGIS-K8S-004", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-005: readOnlyRootFilesystem: false
// ---------------------------------------------------------------------------

func TestK8S005(t *testing.T) {
	bad := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {readOnlyRootFilesystem: false}
`
	mustFire(t, bad, "AEGIS-K8S-005", 1)
	good := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext: {readOnlyRootFilesystem: true}
`
	mustFire(t, good, "AEGIS-K8S-005", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-006: container without resource limits
// ---------------------------------------------------------------------------

func TestK8S006(t *testing.T) {
	bad := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, bad, "AEGIS-K8S-006", 1)
	partial := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    resources: {limits: {cpu: "500m"}}
`
	mustFire(t, partial, "AEGIS-K8S-006", 1) // memory missing
	mustFire(t, basePod, "AEGIS-K8S-006", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-007/008/009: host namespaces
// ---------------------------------------------------------------------------

func TestK8S007_009(t *testing.T) {
	for _, tc := range []struct{ attr, id string }{
		{"hostNetwork", "AEGIS-K8S-007"},
		{"hostPID", "AEGIS-K8S-008"},
		{"hostIPC", "AEGIS-K8S-009"},
	} {
		bad := "apiVersion: v1\nkind: Pod\nmetadata: {name: app}\nspec:\n  " +
			tc.attr + ": true\n  containers:\n  - {name: app, image: nginx:1.25.3}\n"
		mustFire(t, bad, tc.id, 1)
		mustFire(t, basePod, tc.id, 0)
	}
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-010: service account token automount
// ---------------------------------------------------------------------------

func TestK8S010(t *testing.T) {
	explicit := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  automountServiceAccountToken: true
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, explicit, "AEGIS-K8S-010", 1)
	customSA := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  serviceAccountName: custom
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, customSA, "AEGIS-K8S-010", 1)
	disabled := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  serviceAccountName: custom
  automountServiceAccountToken: false
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, disabled, "AEGIS-K8S-010", 0)
	mustFire(t, basePod, "AEGIS-K8S-010", 0) // default SA, absent: quiet
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-011: hostPath volume
// ---------------------------------------------------------------------------

func TestK8S011(t *testing.T) {
	bad := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx:1.25.3}
  volumes:
  - name: hostvol
    hostPath: {path: /var/run/docker.sock}
`
	mustFire(t, bad, "AEGIS-K8S-011", 1)
	mustFire(t, basePod, "AEGIS-K8S-011", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-012/013: image hygiene
// ---------------------------------------------------------------------------

func TestK8S012_013(t *testing.T) {
	noTag := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx}
`
	mustFire(t, noTag, "AEGIS-K8S-012", 1)
	latest := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx:latest}
`
	mustFire(t, latest, "AEGIS-K8S-012", 1)
	mustFire(t, basePod, "AEGIS-K8S-012", 0)

	never := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx:1.25.3, imagePullPolicy: Never}
`
	mustFire(t, never, "AEGIS-K8S-013", 1)
	mustFire(t, basePod, "AEGIS-K8S-013", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-014/015: probes
// ---------------------------------------------------------------------------

func TestK8S014_015(t *testing.T) {
	bad := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, bad, "AEGIS-K8S-014", 1)
	mustFire(t, bad, "AEGIS-K8S-015", 1)
	mustFire(t, basePod, "AEGIS-K8S-014", 0)
	mustFire(t, basePod, "AEGIS-K8S-015", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-016: capabilities add ALL
// ---------------------------------------------------------------------------

func TestK8S016(t *testing.T) {
	bad := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext:
      capabilities: {add: [ALL]}
`
	mustFire(t, bad, "AEGIS-K8S-016", 1)
	good := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext:
      capabilities: {add: [NET_BIND_SERVICE], drop: [ALL]}
`
	mustFire(t, good, "AEGIS-K8S-016", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-017: seccompProfile Unconfined
// ---------------------------------------------------------------------------

func TestK8S017(t *testing.T) {
	bad := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    securityContext:
      seccompProfile: {type: Unconfined}
`
	mustFire(t, bad, "AEGIS-K8S-017", 1)
	good := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext:
    seccompProfile: {type: RuntimeDefault}
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, good, "AEGIS-K8S-017", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-018: shareProcessNamespace
// ---------------------------------------------------------------------------

func TestK8S018(t *testing.T) {
	bad := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  shareProcessNamespace: true
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, bad, "AEGIS-K8S-018", 1)
	mustFire(t, basePod, "AEGIS-K8S-018", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-019: pod-level runAsUser: 0
// ---------------------------------------------------------------------------

func TestK8S019(t *testing.T) {
	bad := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {runAsUser: 0}
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, bad, "AEGIS-K8S-019", 1)
	good := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {runAsUser: 1000}
  containers:
  - {name: app, image: nginx:1.25.3}
`
	mustFire(t, good, "AEGIS-K8S-019", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-020: Service exposed
// ---------------------------------------------------------------------------

func TestK8S020(t *testing.T) {
	lb := `apiVersion: v1
kind: Service
metadata: {name: web}
spec:
  type: LoadBalancer
  ports:
  - {port: 80}
`
	mustFire(t, lb, "AEGIS-K8S-020", 1)
	np := `apiVersion: v1
kind: Service
metadata: {name: web}
spec:
  type: NodePort
  ports:
  - {port: 80}
`
	mustFire(t, np, "AEGIS-K8S-020", 1)
	clusterIP := `apiVersion: v1
kind: Service
metadata: {name: web}
spec:
  type: ClusterIP
  ports:
  - {port: 80}
`
	mustFire(t, clusterIP, "AEGIS-K8S-020", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-021: Ingress without TLS
// ---------------------------------------------------------------------------

func TestK8S021(t *testing.T) {
	bad := `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web}
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service: {name: web, port: {number: 80}}
`
	mustFire(t, bad, "AEGIS-K8S-021", 1)
	good := `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web}
spec:
  tls:
  - hosts: [example.com]
    secretName: web-tls
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service: {name: web, port: {number: 80}}
`
	mustFire(t, good, "AEGIS-K8S-021", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-022: RBAC wildcard
// ---------------------------------------------------------------------------

func TestK8S022(t *testing.T) {
	bad := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: bad}
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: [get, list]
`
	mustFire(t, bad, "AEGIS-K8S-022", 1)
	badVerbs := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: bad, namespace: default}
rules:
- apiGroups: [""]
  resources: [pods]
  verbs: ["*"]
`
	mustFire(t, badVerbs, "AEGIS-K8S-022", 1)
	good := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: ok, namespace: default}
rules:
- apiGroups: [""]
  resources: [pods]
  verbs: [get, list]
`
	mustFire(t, good, "AEGIS-K8S-022", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-023: binding to cluster-admin
// ---------------------------------------------------------------------------

func TestK8S023(t *testing.T) {
	bad := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: bad}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects:
- {kind: ServiceAccount, name: default, namespace: default}
`
	mustFire(t, bad, "AEGIS-K8S-023", 1)
	good := `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ok, namespace: default}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: view}
subjects:
- {kind: ServiceAccount, name: default, namespace: default}
`
	mustFire(t, good, "AEGIS-K8S-023", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-024: stdin+tty
// ---------------------------------------------------------------------------

func TestK8S024(t *testing.T) {
	bad := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
  - {name: app, image: nginx:1.25.3, stdin: true, tty: true}
`
	mustFire(t, bad, "AEGIS-K8S-024", 1)
	mustFire(t, basePod, "AEGIS-K8S-024", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-025: ConfigMap with sensitive keys
// ---------------------------------------------------------------------------

func TestK8S025(t *testing.T) {
	bad := `apiVersion: v1
kind: ConfigMap
metadata: {name: cfg}
data:
  db_password: hunter2
  log_level: info
`
	mustFire(t, bad, "AEGIS-K8S-025", 1)
	good := `apiVersion: v1
kind: ConfigMap
metadata: {name: cfg}
data:
  log_level: info
`
	mustFire(t, good, "AEGIS-K8S-025", 0)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-026: secret in env
// ---------------------------------------------------------------------------

func TestK8S026(t *testing.T) {
	bad := `apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  replicas: 1
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      securityContext: {runAsNonRoot: true}
      containers:
      - name: app
        image: myapp:1.0
        env:
        - {name: DB_PASSWORD, value: Sup3rSecret!-prod-2024}
        - {name: API_TOKEN, value: tok_live_abc}
        - {name: LOG_LEVEL, value: info}
`
	mustFire(t, bad, "AEGIS-K8S-026", 1)
	// valueFrom secretKeyRef is the correct pattern: quiet.
	good := `apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      securityContext: {runAsNonRoot: true}
      containers:
      - name: app
        image: myapp:1.0
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef: {name: db, key: password}
        - {name: LOG_LEVEL, value: info}
`
	mustFire(t, good, "AEGIS-K8S-026", 0)
	// Placeholders and expansions are not leaked secrets.
	ph := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
  - name: app
    image: myapp:1.0
    env:
    - {name: DB_PASSWORD, value: changeme}
    - {name: API_TOKEN, value: $(TOKEN_FROM_FILE)}
`
	mustFire(t, ph, "AEGIS-K8S-026", 0)
	// KEYBOARD is not a secret name; ENCRYPTION_KEY is.
	kb := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
  - name: app
    image: myapp:1.0
    env:
    - {name: KEYBOARD_LAYOUT, value: us}
`
	mustFire(t, kb, "AEGIS-K8S-026", 0)
	ek := `apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
  - name: app
    image: myapp:1.0
    env:
    - {name: ENCRYPTION_KEY, value: abcdef123456}
`
	mustFire(t, ek, "AEGIS-K8S-026", 1)
}

// ---------------------------------------------------------------------------
// AEGIS-K8S-027: no securityContext
// ---------------------------------------------------------------------------

func TestK8S027(t *testing.T) {
	bad := `apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      containers:
      - {name: app, image: myapp:1.0}
`
	mustFire(t, bad, "AEGIS-K8S-027", 1)
	// Pod-level context alone suffices.
	podLevel := `apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      securityContext: {runAsNonRoot: true}
      containers:
      - {name: app, image: myapp:1.0}
`
	mustFire(t, podLevel, "AEGIS-K8S-027", 0)
	// Container-level context alone suffices.
	containerLevel := `apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      containers:
      - name: app
        image: myapp:1.0
        securityContext: {runAsNonRoot: true}
`
	mustFire(t, containerLevel, "AEGIS-K8S-027", 0)
	// Non-workload kinds never fire.
	svc := `apiVersion: v1
kind: Service
metadata: {name: app}
spec:
  selector: {app: app}
  ports: [{port: 80}]
`
	mustFire(t, svc, "AEGIS-K8S-027", 0)
}
