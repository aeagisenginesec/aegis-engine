package docker

import (
	"testing"

	"aegis/internal/adapter/dockerfile"
	"aegis/internal/ir"
)

// Phase B tests: AEGIS-DOCKER-038 (multistage secret copy), the
// AEGIS-DOCKER-003 ARG->ENV passthrough / credential-URL extension, and
// the AEGIS-DOCKER-021 *.env suffix fix.

// parseStages parses a (possibly multi-stage) Dockerfile.
func parseStages(t *testing.T, src string) []ir.Resource {
	t.Helper()
	rs, _, err := dockerfile.New().Parse("Dockerfile", []byte(src))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return rs
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-038: secret file from builder stage copied into final image
// ---------------------------------------------------------------------------

func TestDocker038_EnvCopiedFromBuilderFires(t *testing.T) {
	src := "FROM golang:1.22-bookworm AS build\nCOPY .env /src/.env\nFROM debian:bookworm-slim\nCOPY --from=build /src/.env /app/.env\n"
	rs := parseStages(t, src)
	if len(rs) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(rs))
	}
	expectFinding(t, multistageSecretCopy{}, rs[1], 1)
	// The builder stage itself never fires 038.
	expectFinding(t, multistageSecretCopy{}, rs[0], 0)
}

func TestDocker038_PrivateKeyCopiedFromBuilderFires(t *testing.T) {
	src := "FROM alpine AS build\nCOPY id_rsa /root/.ssh/id_rsa\nFROM alpine\nCOPY --from=build /root/.ssh/id_rsa /root/.ssh/id_rsa\n"
	rs := parseStages(t, src)
	expectFinding(t, multistageSecretCopy{}, rs[1], 1)
}

func TestDocker038_NumericStageRefFires(t *testing.T) {
	src := "FROM alpine AS build\nCOPY app.env /build/app.env\nFROM alpine\nCOPY --from=0 /build/app.env /app/app.env\n"
	rs := parseStages(t, src)
	expectFinding(t, multistageSecretCopy{}, rs[1], 1)
}

func TestDocker038_NonSecretCopyQuiet(t *testing.T) {
	src := "FROM golang:1.22-bookworm AS build\nRUN go build -o /app/server .\nFROM debian:bookworm-slim\nCOPY --from=build /app/server /app/server\n"
	rs := parseStages(t, src)
	expectFinding(t, multistageSecretCopy{}, rs[1], 0)
}

func TestDocker038_DirectCopyQuiet(t *testing.T) {
	// A direct COPY of .env in the final stage is DOCKER-021's
	// territory, not 038: no --from means no builder-stage leak.
	src := "FROM debian:bookworm-slim\nCOPY .env /app/.env\n"
	expectFinding(t, multistageSecretCopy{}, stage(t, src), 0)
}

func TestDocker038_SecretLeftInBuilderQuiet(t *testing.T) {
	src := "FROM golang:1.22-bookworm AS build\nCOPY .env /src/.env\nRUN go build -o /app/server .\nFROM debian:bookworm-slim\nCOPY --from=build /app/server /app/server\n"
	rs := parseStages(t, src)
	expectFinding(t, multistageSecretCopy{}, rs[1], 0)
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-003: ARG->ENV passthrough + credential URLs
// ---------------------------------------------------------------------------

func TestDocker003_ArgPassthroughFires(t *testing.T) {
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nARG DB_PASSWORD=x\nENV DB_PASSWORD=${DB_PASSWORD}\n"), 1)
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nARG API_KEY\nENV API_KEY=$API_KEY\n"), 1)
	// Default-operator expansion still passes the ARG value through.
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nARG DB_PASSWORD\nENV DB_PASSWORD=${DB_PASSWORD:-changeme}\n"), 1)
}

func TestDocker003_UndeclaredExpansionQuiet(t *testing.T) {
	// No ARG declared: $DB_PASS expands to empty, nothing is baked in.
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nENV DB_PASSWORD=$DB_PASS\n"), 0)
}

func TestDocker003_CredentialURLFires(t *testing.T) {
	// URL embedding credentials, even under a non-secret name.
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nENV APP_URL=postgres://appuser:s3cr3t@db:5432/app\n"), 1)
	// Plain URL without credentials stays quiet.
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nENV APP_URL=https://example.com/api\n"), 0)
}

func TestDocker003_NewSecretHints(t *testing.T) {
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nENV MASTER_KEY=abc123\n"), 1)
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nENV DATABASE_URL=postgres://db:5432/app\n"), 1)
	expectFinding(t, envSecrets{}, stage(t, "FROM ubuntu:22.04\nENV DB_URL=mysql://db:3306/app\n"), 1)
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-021: *.env suffix forms
// ---------------------------------------------------------------------------

func TestDocker021_DeployEnvFires(t *testing.T) {
	expectFinding(t, sensitiveCopy{}, stage(t, "FROM ubuntu:22.04\nCOPY deploy.env /app/\n"), 1)
	expectFinding(t, sensitiveCopy{}, stage(t, "FROM ubuntu:22.04\nCOPY config/.env.local /app/\n"), 1)
	expectFinding(t, sensitiveCopy{}, stage(t, "FROM ubuntu:22.04\nCOPY .env /app/\n"), 1)
	expectFinding(t, sensitiveCopy{}, stage(t, "FROM ubuntu:22.04\nCOPY config.yaml /app/\n"), 0)
}
