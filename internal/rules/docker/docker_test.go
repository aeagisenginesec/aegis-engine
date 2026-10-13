package docker

import (
	"strings"
	"testing"

	"aegis/internal/adapter/dockerfile"
	"aegis/internal/ir"
)

func stage(t *testing.T, src string) ir.Resource {
	t.Helper()
	rs, _, err := dockerfile.New().Parse("Dockerfile", []byte(src))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(rs))
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

func Test001_LatestTag(t *testing.T) {
	expectFinding(t, latestTag{}, stage(t, "FROM ubuntu:latest\n"), 1)
	expectFinding(t, latestTag{}, stage(t, "FROM ubuntu\n"), 1) // implicit latest
	expectFinding(t, latestTag{}, stage(t, "FROM ubuntu:22.04\n"), 0)
	expectFinding(t, latestTag{}, stage(t, "FROM ubuntu@sha256:abc123\n"), 0)
	expectFinding(t, latestTag{}, stage(t, "FROM ubuntu:LATEST\n"), 1)
}

func Test002_RootUser(t *testing.T) {
	expectFinding(t, noNonRootUser{}, stage(t, "FROM ubuntu:22.04\n"), 1) // no USER
	expectFinding(t, noNonRootUser{}, stage(t, "FROM ubuntu:22.04\nUSER root\n"), 1)
	expectFinding(t, noNonRootUser{}, stage(t, "FROM ubuntu:22.04\nUSER 0\n"), 1)
	expectFinding(t, noNonRootUser{}, stage(t, "FROM ubuntu:22.04\nUSER appuser\n"), 0)
	expectFinding(t, noNonRootUser{}, stage(t, "FROM ubuntu:22.04\nUSER 1001\n"), 0)
}

// Test002_BuildStageRootQuiet: a multi-stage build's build stage runs
// as root legitimately; only the final stage is judged. (Round-3 FP:
// DOCKER-002 fired on build stages that never run.)
func Test002_BuildStageRootQuiet(t *testing.T) {
	src := "FROM golang:1.22-bookworm AS build\nWORKDIR /src\nCOPY . .\nRUN go build -o /app/server .\nFROM debian:bookworm-slim\nCOPY --from=build /app/server /app/server\nRUN useradd -m app\nUSER app\nCMD [\"/app/server\"]\n"
	rs, _, err := dockerfile.New().Parse("Dockerfile", []byte(src))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(rs))
	}
	if got := runRule(noNonRootUser{}, rs[0]); len(got) != 0 {
		t.Fatalf("build stage must stay quiet for 002, got %+v", got)
	}
	if got := runRule(noNonRootUser{}, rs[1]); len(got) != 0 {
		t.Fatalf("final stage with USER app must stay quiet, got %+v", got)
	}
	// A final stage running as root still fires.
	src2 := "FROM golang:1.22-bookworm AS build\nRUN go build -o /app/server .\nFROM debian:bookworm-slim\nCOPY --from=build /app/server /app/server\nCMD [\"/app/server\"]\n"
	rs2, _, err := dockerfile.New().Parse("Dockerfile", []byte(src2))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if got := runRule(noNonRootUser{}, rs2[1]); len(got) != 1 {
		t.Fatalf("final stage without USER must fire 002, got %+v", got)
	}
}

func Test003_EnvSecrets(t *testing.T) {
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nENV DB_PASSWORD=s3cr3t\n"), 1)
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nENV API_KEY=\"abc123\" TOKEN=$VAULT_TOKEN\n"), 1) // only API_KEY (TOKEN is expansion)
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nENV APP_ENV=production\n"), 0)
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nENV DB_PASSWORD=$DB_PASS\n"), 0) // not literal
}

func Test004_AddInsteadOfCopy(t *testing.T) {
	expectFinding(t, addInsteadOfCopy{}, stage(t, "FROM ubuntu:22.04\nADD app.tar.gz /app/\n"), 1)
	expectFinding(t, addInsteadOfCopy{}, stage(t, "FROM ubuntu:22.04\nCOPY app /app/\n"), 0)
}

func Test005_NoHealthcheck(t *testing.T) {
	expectFinding(t, noHealthcheck{}, stage(t, "FROM ubuntu:22.04\n"), 1)
	expectFinding(t, noHealthcheck{}, stage(t, "FROM ubuntu:22.04\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"), 0)
	expectFinding(t, noHealthcheck{}, stage(t, "FROM ubuntu:22.04\nHEALTHCHECK NONE\n"), 1)
}

func Test006_ExposedSSH(t *testing.T) {
	expectFinding(t, exposedSSH{}, stage(t, "FROM ubuntu:22.04\nEXPOSE 22\n"), 1)
	expectFinding(t, exposedSSH{}, stage(t, "FROM ubuntu:22.04\nEXPOSE 22/tcp 8080\n"), 1)
	expectFinding(t, exposedSSH{}, stage(t, "FROM ubuntu:22.04\nEXPOSE 8080\n"), 0)
}

func Test007_AptNoRecommends(t *testing.T) {
	expectFinding(t, aptNoRecommends{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\n"), 1)
	expectFinding(t, aptNoRecommends{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y --no-install-recommends curl\n"), 0)
	expectFinding(t, aptNoRecommends{}, stage(t, "FROM ubuntu:22.04\nRUN echo hello\n"), 0)
}

func Test008_AptUpdateNoClean(t *testing.T) {
	expectFinding(t, aptUpdateNoClean{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\n"), 1)
	expectFinding(t, aptUpdateNoClean{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n"), 0)
	expectFinding(t, aptUpdateNoClean{}, stage(t, "FROM ubuntu:22.04\nRUN echo hello\n"), 0)
}

func Test009_SudoUsage(t *testing.T) {
	expectFinding(t, sudoUsage{}, stage(t, "FROM ubuntu:22.04\nRUN sudo apt-get update\n"), 1)
	expectFinding(t, sudoUsage{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update\n"), 0)
}

func Test010_UntrustedRegistry(t *testing.T) {
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM ubuntu:22.04\n"), 0) // official library
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM docker.io/library/ubuntu:22.04\n"), 0)
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM myuser/myapp:1.0\n"), 1) // not library
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM gcr.io/proj/app:1.0\n"), 1)
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM registry.example.com/app:1.0\n"), 1)
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM gcr.io/proj/app@sha256:abc123\n"), 0) // digest-pinned
}

// Test010_FirstPartyRegistries: Google's own GCR namespaces, the
// Kubernetes registries, and MCR are first-party and trusted; arbitrary
// customer projects on gcr.io stay untrusted. (Round-3 FP: gcr.io
// distroless images misclassified as untrusted.)
func Test010_FirstPartyRegistries(t *testing.T) {
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM gcr.io/distroless/static-debian12:nonroot\n"), 0)
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM gcr.io/google-containers/pause:3.9\n"), 0)
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM eu.gcr.io/distroless/static-debian12:nonroot\n"), 0)
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM registry.k8s.io/pause:3.9\n"), 0)
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM k8s.gcr.io/pause:3.9\n"), 0)
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM mcr.microsoft.com/dotnet/aspnet:8.0\n"), 0)
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM gcr.io/evil-corp/app:1.0\n"), 1)
	expectFinding(t, untrustedRegistry{}, stage(t, "FROM marketplace.gcr.io/google/distroless:1.0\n"), 1)
}

func TestRules_IDOrder(t *testing.T) {
	rules := Rules()
	if len(rules) != 36 {
		t.Fatalf("want 36 rules, got %d", len(rules))
	}
	for i, r := range rules {
		want := "AEGIS-DOCKER-" + pad3(i+1)
		if r.ID() != want {
			t.Fatalf("want %s at %d, got %s", want, i, r.ID())
		}
		if r.Title() == "" || r.Description() == "" {
			t.Fatalf("empty metadata: %s", want)
		}
		if !r.AppliesTo("docker_stage") {
			t.Fatalf("%s does not apply to docker_stage", want)
		}
		if r.AppliesTo("aws_s3_bucket") {
			t.Fatalf("%s applies to non-docker resource", want)
		}
	}
}

func TestMultiStage_AllRules(t *testing.T) {
	src := `FROM golang:1.21 AS builder
ENV GO111MODULE=on
RUN go build -o /app .
FROM ubuntu:latest
COPY --from=builder /app /app
EXPOSE 22
ADD https://example.com/data.tar.gz /data/
RUN apt-get update && apt-get install -y curl && sudo echo done
ENV DB_PASSWORD=s3cr3t
`
	rs, _, err := dockerfile.New().Parse("Dockerfile", []byte(src))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(rs))
	}
	// Builder stage: latestTag fires (golang:1.21 is pinned, so no);
	// runtime stage should fire 001, 002, 003, 004, 005, 006, 007, 008, 009.
	runtime := rs[1]
	fired := map[string]bool{}
	for _, rule := range Rules() {
		for _, f := range runRule(rule, runtime) {
			fired[f.RuleID] = true
		}
	}
	for _, want := range []string{
		"AEGIS-DOCKER-001", "AEGIS-DOCKER-002", "AEGIS-DOCKER-003",
		"AEGIS-DOCKER-004", "AEGIS-DOCKER-005", "AEGIS-DOCKER-006",
		"AEGIS-DOCKER-007", "AEGIS-DOCKER-008", "AEGIS-DOCKER-009",
	} {
		if !fired[want] {
			t.Errorf("expected %s to fire on runtime stage", want)
		}
	}
	// Builder stage: only 005 (no healthcheck) should fire. 002 (runs
	// as root) does NOT fire on build stages: they legitimately run as
	// root and never ship (round-3 FP fix).
	builder := rs[0]
	bfired := map[string]bool{}
	for _, rule := range Rules() {
		for _, f := range runRule(rule, builder) {
			bfired[f.RuleID] = true
		}
	}
	if bfired["AEGIS-DOCKER-002"] {
		t.Error("builder stage must not fire 002 (build stages run as root by design)")
	}
	if !bfired["AEGIS-DOCKER-005"] {
		t.Error("builder stage should fire 005")
	}
	if bfired["AEGIS-DOCKER-001"] {
		t.Error("builder uses pinned golang:1.21, 001 should not fire")
	}
}
