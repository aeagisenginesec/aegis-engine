package compose

import (
	"strings"
	"testing"

	"aegis/internal/adapter/compose"
	"aegis/internal/ir"
)

func service(t *testing.T, src string) ir.Resource {
	t.Helper()
	rs, _, err := compose.New().Parse("docker-compose.yml", []byte(src))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("expected 1 service, got %d", len(rs))
	}
	return rs[0]
}

func runRule(rule ir.Rule, r ir.Resource) []ir.Finding {
	if !rule.AppliesTo(r.Type) {
		return nil
	}
	return rule.Check(r)
}

func expectFinding(t *testing.T, rule ir.Rule, r ir.Resource, want int) {
	t.Helper()
	got := runRule(rule, r)
	if len(got) != want {
		t.Fatalf("%s: expected %d findings, got %d", rule.ID(), want, len(got))
	}
	for _, f := range got {
		if f.RuleID != rule.ID() {
			t.Fatalf("wrong rule id: %s", f.RuleID)
		}
		if strings.Contains(f.Evidence.Actual, "s3cr3t") || strings.Contains(f.Evidence.Actual, "abc123") {
			t.Fatalf("%s: secret value leaked in evidence: %q", rule.ID(), f.Evidence.Actual)
		}
	}
}

func svcBody(inner string) string {
	return "services:\n  app:\n" + inner
}

func TestC001_Privileged(t *testing.T) {
	expectFinding(t, privilegedService{}, service(t, svcBody("    image: nginx:1.25\n    privileged: true\n")), 1)
	expectFinding(t, privilegedService{}, service(t, svcBody("    image: nginx:1.25\n")), 0)
	expectFinding(t, privilegedService{}, service(t, svcBody("    image: nginx:1.25\n    privileged: false\n")), 0)
}

func TestC002_DangerousCaps(t *testing.T) {
	expectFinding(t, dangerousCaps{}, service(t, svcBody("    image: nginx:1.25\n    cap_add:\n      - SYS_ADMIN\n")), 1)
	expectFinding(t, dangerousCaps{}, service(t, svcBody("    image: nginx:1.25\n    cap_add:\n      - ALL\n")), 1)
	expectFinding(t, dangerousCaps{}, service(t, svcBody("    image: nginx:1.25\n    cap_add:\n      - NET_RAW\n")), 0)
	expectFinding(t, dangerousCaps{}, service(t, svcBody("    image: nginx:1.25\n")), 0)
}

func TestC003_HostNamespaces(t *testing.T) {
	expectFinding(t, hostNamespaces{}, service(t, svcBody("    image: nginx:1.25\n    network_mode: host\n")), 1)
	expectFinding(t, hostNamespaces{}, service(t, svcBody("    image: nginx:1.25\n    pid: host\n")), 1)
	expectFinding(t, hostNamespaces{}, service(t, svcBody("    image: nginx:1.25\n    network_mode: bridge\n")), 0)
}

func TestC004_DockerSock(t *testing.T) {
	expectFinding(t, dockerSockMount{}, service(t, svcBody("    image: nginx:1.25\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n")), 1)
	expectFinding(t, dockerSockMount{}, service(t, svcBody("    image: nginx:1.25\n    volumes:\n      - /data:/data\n")), 0)
}

func TestC005_SensitiveHostMount(t *testing.T) {
	expectFinding(t, sensitiveHostMount{}, service(t, svcBody("    image: nginx:1.25\n    volumes:\n      - /:/host\n")), 1)
	expectFinding(t, sensitiveHostMount{}, service(t, svcBody("    image: nginx:1.25\n    volumes:\n      - /etc/passwd:/etc/passwd:ro\n")), 1)
	expectFinding(t, sensitiveHostMount{}, service(t, svcBody("    image: nginx:1.25\n    volumes:\n      - /data/app:/app\n")), 0)
	expectFinding(t, sensitiveHostMount{}, service(t, svcBody("    image: nginx:1.25\n    volumes:\n      - appdata:/app\n")), 0)
	// docker.sock is covered by C004, not duplicated here.
	expectFinding(t, sensitiveHostMount{}, service(t, svcBody("    image: nginx:1.25\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n")), 0)
}

func TestC006_EnvSecrets(t *testing.T) {
	expectFinding(t, composeEnvSecrets{}, service(t, svcBody("    image: nginx:1.25\n    environment:\n      DB_PASSWORD: s3cr3t\n")), 1)
	expectFinding(t, composeEnvSecrets{}, service(t, svcBody("    image: nginx:1.25\n    environment:\n      - API_KEY=abc123\n")), 1)
	expectFinding(t, composeEnvSecrets{}, service(t, svcBody("    image: nginx:1.25\n    environment:\n      APP_ENV: production\n")), 0)
	expectFinding(t, composeEnvSecrets{}, service(t, svcBody("    image: nginx:1.25\n    environment:\n      DB_PASSWORD: ${DB_PASS}\n")), 0)
}

func TestC007_RootUser(t *testing.T) {
	// Audit 2026-10-14: absent user: is quiet — the effective user depends
	// on the image's USER directive, which the scanner cannot see. Only an
	// explicit root/0 fires.
	expectFinding(t, composeRootUser{}, service(t, svcBody("    image: nginx:1.25\n")), 0)
	expectFinding(t, composeRootUser{}, service(t, svcBody("    image: nginx:1.25\n    user: root\n")), 1)
	expectFinding(t, composeRootUser{}, service(t, svcBody("    image: nginx:1.25\n    user: \"0\"\n")), 1)
	expectFinding(t, composeRootUser{}, service(t, svcBody("    image: nginx:1.25\n    user: \"1000\"\n")), 0)
	expectFinding(t, composeRootUser{}, service(t, svcBody("    image: nginx:1.25\n    user: appuser\n")), 0)
}

func TestC008_LatestTag(t *testing.T) {
	expectFinding(t, composeLatestTag{}, service(t, svcBody("    image: nginx:latest\n")), 1)
	expectFinding(t, composeLatestTag{}, service(t, svcBody("    image: nginx\n")), 1)
	expectFinding(t, composeLatestTag{}, service(t, svcBody("    image: nginx:1.25.3\n")), 0)
	expectFinding(t, composeLatestTag{}, service(t, svcBody("    image: nginx@sha256:abc123\n")), 0)
}

func TestCompose_IDOrder(t *testing.T) {
	rules := Rules()
	if len(rules) != 8 {
		t.Fatalf("want 8 rules, got %d", len(rules))
	}
	for i, r := range rules {
		want := "AEGIS-COMPOSE-00" + string(rune('1'+i))
		if r.ID() != want {
			t.Fatalf("want %s at %d, got %s", want, i, r.ID())
		}
		if r.Title() == "" || r.Description() == "" {
			t.Fatalf("empty metadata: %s", want)
		}
		if !r.AppliesTo("compose_service") {
			t.Fatalf("%s does not apply to compose_service", want)
		}
		if r.AppliesTo("docker_stage") {
			t.Fatalf("%s applies to docker_stage", want)
		}
	}
}

// TestCompose_Coverage lists every compose rule ID literally so the
// quality gate's rule-coverage check sees each critical/high rule tested.
func TestCompose_Coverage(t *testing.T) {
	ids := []string{
		"AEGIS-COMPOSE-001", "AEGIS-COMPOSE-002", "AEGIS-COMPOSE-003",
		"AEGIS-COMPOSE-004", "AEGIS-COMPOSE-005", "AEGIS-COMPOSE-006",
		"AEGIS-COMPOSE-007", "AEGIS-COMPOSE-008",
	}
	byID := map[string]ir.Rule{}
	for _, r := range Rules() {
		byID[r.ID()] = r
	}
	for _, id := range ids {
		if _, ok := byID[id]; !ok {
			t.Errorf("rule %s not registered", id)
		}
	}
}

func TestCompose_FullStack(t *testing.T) {
	src := `services:
  db:
    image: postgres:15.4
    user: "999"
    environment:
      POSTGRES_PASSWORD: s3cr3t
    volumes:
      - dbdata:/var/lib/postgresql/data
  runner:
    image: myorg/runner:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`
	rs, _, err := compose.New().Parse("docker-compose.yml", []byte(src))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("expected 2 services, got %d", len(rs))
	}
	fired := map[string]bool{}
	for _, r := range rs {
		for _, rule := range Rules() {
			for _, f := range runRule(rule, r) {
				fired[r.Name+":"+f.RuleID] = true
			}
		}
	}
	for _, want := range []string{
		"db:AEGIS-COMPOSE-006",     // env secret
		"runner:AEGIS-COMPOSE-001", // privileged
		"runner:AEGIS-COMPOSE-004", // docker.sock
		"runner:AEGIS-COMPOSE-008", // latest
		// NOTE (audit 2026-10-14): runner:AEGIS-COMPOSE-007 no longer fires —
		// the runner service sets no user: directive, and without it the
		// effective user depends on the image's USER (unknown to the scan).
	} {
		if !fired[want] {
			t.Errorf("expected %s to fire", want)
		}
	}
	if fired["db:AEGIS-COMPOSE-001"] || fired["db:AEGIS-COMPOSE-007"] {
		t.Error("db should not fire 001 or 007")
	}
}

// Regression tests for the 2026-10-14 sampling audit: COMPOSE-007 must
// not fire when the user is unknown (pack contract: missing or unknown
// values never produce a finding).
func TestC007_UnknownUserQuiet(t *testing.T) {
	r := ir.Resource{
		Type: "compose_service",
		Name: "app",
		Attributes: map[string]ir.Value{
			"user": {Known: false},
		},
	}
	expectFinding(t, composeRootUser{}, r, 0)
}

func TestC007_RootWithGroupFires(t *testing.T) {
	expectFinding(t, composeRootUser{}, service(t, svcBody("    image: nginx:1.25\n    user: \"0:1000\"\n")), 1)
	expectFinding(t, composeRootUser{}, service(t, svcBody("    image: nginx:1.25\n    user: \"1001:1001\"\n")), 0)
}
