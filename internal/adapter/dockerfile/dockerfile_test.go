package dockerfile

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

func parse(t *testing.T, name, src string) []ir.Resource {
	t.Helper()
	a := New()
	rs, _, err := a.Parse(name, []byte(src))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	return rs
}

func TestHandles(t *testing.T) {
	a := New()
	for _, p := range []string{"Dockerfile", "Dockerfile.prod", "app.dockerfile", "dir/Dockerfile.dev"} {
		if !a.Handles(p) {
			t.Errorf("expected Handles(%q) = true", p)
		}
	}
	for _, p := range []string{"main.tf", "docker-compose.yml", "Dockerfilex", "myDockerfile"} {
		if a.Handles(p) {
			t.Errorf("expected Handles(%q) = false", p)
		}
	}
}

func TestParseSingleStage(t *testing.T) {
	src := `FROM ubuntu:22.04
RUN apt-get update
USER appuser
EXPOSE 8080
HEALTHCHECK CMD curl -f http://localhost:8080/ || exit 1
`
	rs := parse(t, "Dockerfile", src)
	if len(rs) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(rs))
	}
	r := rs[0]
	if r.Type != "docker_stage" || r.Name != "stage0" {
		t.Fatalf("unexpected resource: %s", r.Address())
	}
	img, _ := r.Attributes["base_image"].AsString()
	if img != "ubuntu:22.04" {
		t.Fatalf("base_image = %q", img)
	}
	tag, _ := r.Attributes["base_tag"].AsString()
	if tag != "22.04" {
		t.Fatalf("base_tag = %q", tag)
	}
	user, _ := r.Attributes["user"].AsString()
	if user != "appuser" {
		t.Fatalf("user = %q", user)
	}
	hc, _ := r.Attributes["has_healthcheck"].AsBool()
	if !hc {
		t.Fatal("expected has_healthcheck = true")
	}
	ports, _ := r.Attributes["exposed_ports"].AsList()
	if len(ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(ports))
	}
}

func TestParseMultiStage(t *testing.T) {
	src := `FROM golang:1.21 AS builder
RUN go build -o /app .
FROM alpine:3.18 AS runtime
COPY --from=builder /app /app
USER nobody
`
	rs := parse(t, "Dockerfile", src)
	if len(rs) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(rs))
	}
	if rs[0].Name != "builder" || rs[1].Name != "runtime" {
		t.Fatalf("stage names: %q %q", rs[0].Name, rs[1].Name)
	}
	if _, ok := rs[0].Attributes["user"]; ok {
		t.Fatal("builder stage should have no user attribute")
	}
}

func TestParseEnvSecretsRedacted(t *testing.T) {
	src := `FROM ubuntu:22.04
ENV DB_PASSWORD=s3cr3t API_KEY="abc123" NORMAL_VAR=hello OTHER=$EXISTING
`
	rs := parse(t, "Dockerfile", src)
	if len(rs) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(rs))
	}
	names, _ := rs[0].Attributes["env_names"].AsList()
	if len(names) != 4 {
		t.Fatalf("expected 4 env names, got %d", len(names))
	}
	secrets, _ := rs[0].Attributes["env_secrets"].AsList()
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets (DB_PASSWORD, API_KEY), got %d", len(secrets))
	}
	// Values must never be stored.
	for _, s := range secrets {
		m, _ := s.AsMap()
		if _, hasVal := m["value"]; hasVal {
			t.Fatal("secret value stored in resource")
		}
		if _, hasVal := m["secret"]; hasVal {
			t.Fatal("secret value stored in resource")
		}
	}
}

func TestParseMalformedNoCrash(t *testing.T) {
	for _, src := range []string{
		"",
		"\n\n   \n",
		"FROM\n",
		"FROM \nUSER\nEXPOSE\n",
		"GARBAGE LINE WITH NO MEANING\nANOTHER {{{",
		"FROM ubuntu:22.04\\\n", // dangling continuation
		"FROM ubuntu:22.04\nRUN echo \"unclosed quote\nUSER 'x",
		"FROM --platform=linux/amd64 AS b\nFROM scratch\n",
	} {
		rs, diags, err := New().Parse("Dockerfile", []byte(src))
		if err != nil {
			t.Fatalf("Parse(%q) returned error: %v", src, err)
		}
		_ = rs
		_ = diags
	}
}

func TestParseLineContinuation(t *testing.T) {
	src := "FROM ubuntu:22.04\nRUN apt-get update && \\\n    apt-get install -y curl\n"
	rs := parse(t, "Dockerfile", src)
	if len(rs) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(rs))
	}
	runs, _ := rs[0].Attributes["run_commands"].AsList()
	if len(runs) != 1 {
		t.Fatalf("expected 1 RUN (continuation joined), got %d", len(runs))
	}
	cmd, _ := runs[0].AsString()
	if !strings.Contains(cmd, "apt-get install") {
		t.Fatalf("continuation not joined: %q", cmd)
	}
}

func TestParseAddAndSudo(t *testing.T) {
	src := "FROM ubuntu:22.04\nADD https://example.com/x.tar.gz /tmp/\nRUN sudo apt-get update\n"
	rs := parse(t, "Dockerfile", src)
	r := rs[0]
	usesAdd, _ := r.Attributes["uses_add"].AsBool()
	if !usesAdd {
		t.Fatal("expected uses_add = true")
	}
	sudo, _ := r.Attributes["sudo_used"].AsBool()
	if !sudo {
		t.Fatal("expected sudo_used = true")
	}
}

func TestParseUserRootVariants(t *testing.T) {
	for _, src := range []string{
		"FROM ubuntu:22.04\nUSER root\n",
		"FROM ubuntu:22.04\nUSER 0\n",
		"FROM ubuntu:22.04\nUSER root:root\n",
	} {
		rs := parse(t, "Dockerfile", src)
		user, _ := rs[0].Attributes["user"].AsString()
		if user == "root:root" {
			t.Fatalf("group suffix not stripped: %q", user)
		}
	}
}

// Parity (item 2): an unknown Dockerfile instruction must produce a
// warning diagnostic, never vanish silently (a typo'd USER or
// HEALTHCHECK would otherwise look like an absent setting).
func TestUnknownInstructionWarns(t *testing.T) {
	src := "FROM ubuntu:latest\nBOGUSINSTRUCTION something here\nUSER root\n"
	rs, diags, err := Adapter{}.Parse("Dockerfile", []byte(src))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(rs))
	}
	found := false
	for _, d := range diags {
		if d.Level == "warning" && strings.Contains(d.Message, "BOGUSINSTRUCTION") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning diagnostic for unknown instruction, got %v", diags)
	}
}

// Phase B tests: HEALTHCHECK NONE counts as a present directive
// (DOCKER-005 FP fix), and COPY --from sources are surfaced separately
// (DOCKER-038 surface).

func TestParseHealthcheckNonePresent(t *testing.T) {
	rs := parse(t, "Dockerfile", "FROM ubuntu:22.04\nHEALTHCHECK NONE\n")
	if len(rs) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(rs))
	}
	hc, _ := rs[0].Attributes["has_healthcheck"].AsBool()
	if !hc {
		t.Fatal("HEALTHCHECK NONE must set has_healthcheck = true")
	}
	none, _ := rs[0].Attributes["healthcheck_none"].AsBool()
	if !none {
		t.Fatal("HEALTHCHECK NONE must set healthcheck_none = true")
	}
}

func TestParseHealthcheckCmdNotNone(t *testing.T) {
	rs := parse(t, "Dockerfile", "FROM ubuntu:22.04\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n")
	hc, _ := rs[0].Attributes["has_healthcheck"].AsBool()
	if !hc {
		t.Fatal("HEALTHCHECK CMD must set has_healthcheck = true")
	}
	if none, _ := rs[0].Attributes["healthcheck_none"].AsBool(); none {
		t.Fatal("HEALTHCHECK CMD must not set healthcheck_none")
	}
}

func TestParseCopyFromSources(t *testing.T) {
	src := "FROM golang:1.22-bookworm AS build\nCOPY .env /src/.env\nFROM debian:bookworm-slim\nCOPY --from=build /src/.env /app/.env\nCOPY --from=build /app/server /app/server\n"
	rs := parse(t, "Dockerfile", src)
	if len(rs) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(rs))
	}
	v, ok := rs[1].Attributes["copy_from_sources"]
	if !ok {
		t.Fatal("final stage missing copy_from_sources")
	}
	lst, ok := v.AsList()
	if !ok || len(lst) != 2 {
		t.Fatalf("expected 2 copy_from_sources entries, got %v", v.Raw)
	}
	first, ok := lst[0].AsMap()
	if !ok {
		t.Fatalf("copy_from_sources[0] is not a map: %v", lst[0].Raw)
	}
	if s, _ := first["source"].AsString(); s != "/src/.env" {
		t.Errorf("source = %q, want /src/.env", s)
	}
	if s, _ := first["from"].AsString(); s != "build" {
		t.Errorf("from = %q, want build", s)
	}
}
