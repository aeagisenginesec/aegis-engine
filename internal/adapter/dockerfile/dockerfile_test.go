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
