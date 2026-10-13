package docker

import (
	"testing"

	"aegis/internal/adapter/dockerfile"
	"aegis/internal/ir"
)

// multiStage parses a multi-stage Dockerfile and returns all stages.
func multiStage(t *testing.T, src string) []ir.Resource {
	t.Helper()
	rs, _, err := dockerfile.New().Parse("Dockerfile", []byte(src))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return rs
}

func Test011_ArgSecrets(t *testing.T) {
	expectFinding(t, argSecrets{}, stage(t, "FROM ubuntu:22.04\nARG API_KEY=s3cr3t\n"), 1)
	expectFinding(t, argSecrets{}, stage(t, "FROM ubuntu:22.04\nARG DB_PASSWORD=\"abc123\"\n"), 1)
	expectFinding(t, argSecrets{}, stage(t, "FROM ubuntu:22.04\nARG VERSION=1.2.3\n"), 0)
	expectFinding(t, argSecrets{}, stage(t, "FROM ubuntu:22.04\nARG TOKEN\n"), 0) // no default
	expectFinding(t, argSecrets{}, stage(t, "FROM ubuntu:22.04\nARG TOKEN=$VAULT_TOKEN\n"), 0)
	// Global ARG before the first FROM attaches to the first stage.
	expectFinding(t, argSecrets{}, stage(t, "ARG API_KEY=s3cr3t\nFROM ubuntu:22.04\n"), 1)
}

func Test012_CurlPipeShell(t *testing.T) {
	expectFinding(t, curlPipeShell{}, stage(t, "FROM ubuntu:22.04\nRUN curl -sSL https://example.com/install.sh | sh\n"), 1)
	expectFinding(t, curlPipeShell{}, stage(t, "FROM ubuntu:22.04\nRUN wget -qO- https://example.com/x.sh | bash\n"), 1)
	expectFinding(t, curlPipeShell{}, stage(t, "FROM ubuntu:22.04\nRUN curl -sSL -o /tmp/x.sh https://example.com/x.sh && sh /tmp/x.sh\n"), 0)
	expectFinding(t, curlPipeShell{}, stage(t, "FROM ubuntu:22.04\nRUN echo hello | grep h\n"), 0)
}

func Test013_RunChown(t *testing.T) {
	expectFinding(t, runChown{}, stage(t, "FROM ubuntu:22.04\nCOPY app /app\nRUN chown -R appuser /app\n"), 1)
	expectFinding(t, runChown{}, stage(t, "FROM ubuntu:22.04\nCOPY --chown=appuser app /app\n"), 0)
	expectFinding(t, runChown{}, stage(t, "FROM ubuntu:22.04\nRUN echo done\n"), 0)
}

func Test014_Chmod777(t *testing.T) {
	expectFinding(t, chmod777{}, stage(t, "FROM ubuntu:22.04\nRUN chmod -R 777 /app\n"), 1)
	expectFinding(t, chmod777{}, stage(t, "FROM ubuntu:22.04\nRUN chmod 755 /app/run.sh\n"), 0)
	expectFinding(t, chmod777{}, stage(t, "FROM ubuntu:22.04\nRUN chmod a+rwx /tmp/x\n"), 1)
}

func Test015_NoWorkdir(t *testing.T) {
	expectFinding(t, noWorkdir{}, stage(t, "FROM ubuntu:22.04\n"), 1)
	expectFinding(t, noWorkdir{}, stage(t, "FROM ubuntu:22.04\nWORKDIR /app\n"), 0)
}

func Test016_DeprecatedMaintainer(t *testing.T) {
	expectFinding(t, deprecatedMaintainer{}, stage(t, "FROM ubuntu:22.04\nMAINTAINER ops@example.com\n"), 1)
	expectFinding(t, deprecatedMaintainer{}, stage(t, "FROM ubuntu:22.04\nLABEL maintainer=\"ops@example.com\"\n"), 0)
}

func Test017_NoMaintainerLabel(t *testing.T) {
	expectFinding(t, noMaintainerLabel{}, stage(t, "FROM ubuntu:22.04\n"), 1)
	expectFinding(t, noMaintainerLabel{}, stage(t, "FROM ubuntu:22.04\nLABEL maintainer=\"ops@example.com\"\n"), 0)
	expectFinding(t, noMaintainerLabel{}, stage(t, "FROM ubuntu:22.04\nLABEL org.opencontainers.image.authors=\"ops\"\n"), 0)
	expectFinding(t, noMaintainerLabel{}, stage(t, "FROM ubuntu:22.04\nLABEL version=\"1.0\"\n"), 1)
}

func Test018_NoStopsignal(t *testing.T) {
	expectFinding(t, noStopsignal{}, stage(t, "FROM ubuntu:22.04\n"), 1)
	expectFinding(t, noStopsignal{}, stage(t, "FROM ubuntu:22.04\nSTOPSIGNAL SIGTERM\n"), 0)
}

func Test019_OnbuildUsed(t *testing.T) {
	expectFinding(t, onbuildUsed{}, stage(t, "FROM ubuntu:22.04\nONBUILD COPY . /app\n"), 1)
	expectFinding(t, onbuildUsed{}, stage(t, "FROM ubuntu:22.04\nCOPY . /app\n"), 0)
}

func Test020_VolumeDeclared(t *testing.T) {
	expectFinding(t, volumeDeclared{}, stage(t, "FROM ubuntu:22.04\nVOLUME /data\n"), 1)
	expectFinding(t, volumeDeclared{}, stage(t, "FROM ubuntu:22.04\nRUN mkdir /data\n"), 0)
}

func Test021_SensitiveCopy(t *testing.T) {
	expectFinding(t, sensitiveCopy{}, stage(t, "FROM ubuntu:22.04\nCOPY .env /app/.env\n"), 1)
	expectFinding(t, sensitiveCopy{}, stage(t, "FROM ubuntu:22.04\nCOPY id_rsa /root/.ssh/\n"), 1)
	expectFinding(t, sensitiveCopy{}, stage(t, "FROM ubuntu:22.04\nCOPY server.pem /certs/\n"), 1)
	expectFinding(t, sensitiveCopy{}, stage(t, "FROM ubuntu:22.04\nCOPY .git /app/.git\n"), 1)
	expectFinding(t, sensitiveCopy{}, stage(t, "FROM ubuntu:22.04\nCOPY app /app\n"), 0)
	expectFinding(t, sensitiveCopy{}, stage(t, "FROM ubuntu:22.04\nCOPY --from=builder /out/app /app\n"), 0)
}

func Test022_BroadCopyContext(t *testing.T) {
	expectFinding(t, broadCopyContext{}, stage(t, "FROM ubuntu:22.04\nCOPY . /app\n"), 1)
	expectFinding(t, broadCopyContext{}, stage(t, "FROM ubuntu:22.04\nCOPY ./ /app\n"), 1)
	expectFinding(t, broadCopyContext{}, stage(t, "FROM ubuntu:22.04\nCOPY app /app\n"), 0)
}

func Test023_ShellNoPipefail(t *testing.T) {
	expectFinding(t, shellNoPipefail{}, stage(t, "FROM ubuntu:22.04\nSHELL [\"/bin/bash\", \"-c\"]\n"), 1)
	expectFinding(t, shellNoPipefail{}, stage(t, "FROM ubuntu:22.04\nSHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]\n"), 0)
	expectFinding(t, shellNoPipefail{}, stage(t, "FROM ubuntu:22.04\n"), 0)
	expectFinding(t, shellNoPipefail{}, stage(t, "FROM ubuntu:22.04\nSHELL [\"powershell\", \"-command\"]\n"), 0)
}

func Test024_ShellFormCmd(t *testing.T) {
	expectFinding(t, shellFormCmd{}, stage(t, "FROM ubuntu:22.04\nCMD ./app --serve\n"), 1)
	expectFinding(t, shellFormCmd{}, stage(t, "FROM ubuntu:22.04\nCMD [\"./app\", \"--serve\"]\n"), 0)
	expectFinding(t, shellFormCmd{}, stage(t, "FROM ubuntu:22.04\nENTRYPOINT /entry.sh\n"), 1)
	expectFinding(t, shellFormCmd{}, stage(t, "FROM ubuntu:22.04\nENTRYPOINT [\"/entry.sh\"]\n"), 0)
	expectFinding(t, shellFormCmd{}, stage(t, "FROM ubuntu:22.04\n"), 0)
}

func Test025_SingleStageBuild(t *testing.T) {
	expectFinding(t, singleStageBuild{}, stage(t, "FROM golang:1.21\nRUN go build -o /app .\n"), 1)
	expectFinding(t, singleStageBuild{}, stage(t, "FROM ubuntu:22.04\nRUN echo done\n"), 0)
	// Multi-stage: no finding even with a toolchain base.
	rs := multiStage(t, "FROM golang:1.21 AS builder\nRUN go build -o /app .\nFROM alpine:3.19\nCOPY --from=builder /app /app\n")
	expectFinding(t, singleStageBuild{}, rs[0], 0)
	expectFinding(t, singleStageBuild{}, rs[1], 0)
}

func Test026_FullOSBase(t *testing.T) {
	expectFinding(t, fullOSBase{}, stage(t, "FROM ubuntu:22.04\n"), 1)
	expectFinding(t, fullOSBase{}, stage(t, "FROM debian:bookworm-slim\n"), 0) // slim exempt
	expectFinding(t, fullOSBase{}, stage(t, "FROM alpine:3.19\n"), 0)
	expectFinding(t, fullOSBase{}, stage(t, "FROM gcr.io/distroless/base-debian12\n"), 0)
}

func Test027_FloatingMajorTag(t *testing.T) {
	expectFinding(t, floatingMajorTag{}, stage(t, "FROM python:3\n"), 1)
	expectFinding(t, floatingMajorTag{}, stage(t, "FROM node:20\n"), 1)
	expectFinding(t, floatingMajorTag{}, stage(t, "FROM python:3.12.1\n"), 0)
	expectFinding(t, floatingMajorTag{}, stage(t, "FROM python:3.12\n"), 0)
	expectFinding(t, floatingMajorTag{}, stage(t, "FROM python@sha256:abc123\n"), 0)
}

func Test028_PrivilegedPort(t *testing.T) {
	expectFinding(t, privilegedPort{}, stage(t, "FROM ubuntu:22.04\nEXPOSE 25\n"), 1)
	expectFinding(t, privilegedPort{}, stage(t, "FROM ubuntu:22.04\nEXPOSE 80\n"), 0)
	expectFinding(t, privilegedPort{}, stage(t, "FROM ubuntu:22.04\nEXPOSE 443\n"), 0)
	expectFinding(t, privilegedPort{}, stage(t, "FROM ubuntu:22.04\nEXPOSE 22\n"), 0) // covered by 006
	expectFinding(t, privilegedPort{}, stage(t, "FROM ubuntu:22.04\nEXPOSE 8080\n"), 0)
}

func Test029_AptUnpinned(t *testing.T) {
	expectFinding(t, aptUnpinned{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\n"), 1)
	expectFinding(t, aptUnpinned{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl=7.81.0-1ubuntu1\n"), 0)
	expectFinding(t, aptUnpinned{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y --no-install-recommends curl\n"), 1)
	expectFinding(t, aptUnpinned{}, stage(t, "FROM ubuntu:22.04\nRUN echo hello\n"), 0)
}

func Test030_ApkNoCache(t *testing.T) {
	expectFinding(t, apkNoCache{}, stage(t, "FROM alpine:3.19\nRUN apk add curl\n"), 1)
	expectFinding(t, apkNoCache{}, stage(t, "FROM alpine:3.19\nRUN apk add --no-cache curl\n"), 0)
	expectFinding(t, apkNoCache{}, stage(t, "FROM alpine:3.19\nRUN echo hello\n"), 0)
}

func Test031_YumNoClean(t *testing.T) {
	expectFinding(t, yumNoClean{}, stage(t, "FROM fedora:39\nRUN yum install -y curl\n"), 1)
	expectFinding(t, yumNoClean{}, stage(t, "FROM fedora:39\nRUN yum install -y curl && yum clean all\n"), 0)
	expectFinding(t, yumNoClean{}, stage(t, "FROM fedora:39\nRUN dnf install -y curl && dnf clean all\n"), 0)
	expectFinding(t, yumNoClean{}, stage(t, "FROM fedora:39\nRUN echo hello\n"), 0)
}

func Test032_PipNoCacheDir(t *testing.T) {
	expectFinding(t, pipNoCacheDir{}, stage(t, "FROM python:3.12\nRUN pip install requests\n"), 1)
	expectFinding(t, pipNoCacheDir{}, stage(t, "FROM python:3.12\nRUN pip install --no-cache-dir requests\n"), 0)
	expectFinding(t, pipNoCacheDir{}, stage(t, "FROM python:3.12\nRUN pip3 install requests\n"), 1)
}

func Test033_AptUpgrade(t *testing.T) {
	expectFinding(t, aptUpgrade{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get upgrade -y\n"), 1)
	expectFinding(t, aptUpgrade{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get dist-upgrade -y\n"), 1)
	expectFinding(t, aptUpgrade{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\n"), 0)
}

func Test034_RunSecrets(t *testing.T) {
	expectFinding(t, runSecrets{}, stage(t, "FROM ubuntu:22.04\nRUN curl -u admin:s3cr3t https://example.com/api\n"), 1)
	expectFinding(t, runSecrets{}, stage(t, "FROM ubuntu:22.04\nRUN git clone https://user:p4ssw0rd@github.com/org/repo.git\n"), 1)
	expectFinding(t, runSecrets{}, stage(t, "FROM ubuntu:22.04\nRUN export DB_PASSWORD=s3cr3t && ./init.sh\n"), 1)
	expectFinding(t, runSecrets{}, stage(t, "FROM ubuntu:22.04\nRUN export DB_PASSWORD=$DB_PASS && ./init.sh\n"), 0)
	expectFinding(t, runSecrets{}, stage(t, "FROM ubuntu:22.04\nRUN echo hello\n"), 0)
}

func Test035_AddRemoteURL(t *testing.T) {
	expectFinding(t, addRemoteURL{}, stage(t, "FROM ubuntu:22.04\nADD https://example.com/app.tar.gz /app/\n"), 1)
	expectFinding(t, addRemoteURL{}, stage(t, "FROM ubuntu:22.04\nADD app.tar.gz /app/\n"), 0)
	expectFinding(t, addRemoteURL{}, stage(t, "FROM ubuntu:22.04\nCOPY app /app/\n"), 0)
}

// TestExtraRules_Coverage lists every new rule ID literally so the
// quality gate's rule-coverage check (string search over _test.go files)
// sees each critical/high rule exercised.
func TestExtraRules_Coverage(t *testing.T) {
	ids := []string{
		"AEGIS-DOCKER-011", "AEGIS-DOCKER-012", "AEGIS-DOCKER-013",
		"AEGIS-DOCKER-014", "AEGIS-DOCKER-015", "AEGIS-DOCKER-016",
		"AEGIS-DOCKER-017", "AEGIS-DOCKER-018", "AEGIS-DOCKER-019",
		"AEGIS-DOCKER-020", "AEGIS-DOCKER-021", "AEGIS-DOCKER-022",
		"AEGIS-DOCKER-023", "AEGIS-DOCKER-024", "AEGIS-DOCKER-025",
		"AEGIS-DOCKER-026", "AEGIS-DOCKER-027", "AEGIS-DOCKER-028",
		"AEGIS-DOCKER-029", "AEGIS-DOCKER-030", "AEGIS-DOCKER-031",
		"AEGIS-DOCKER-032", "AEGIS-DOCKER-033", "AEGIS-DOCKER-034",
		"AEGIS-DOCKER-035",
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

func pad3(n int) string {
	s := ""
	if n < 10 {
		s = "00"
	} else if n < 100 {
		s = "0"
	}
	return s + itoa2(n)
}

func itoa2(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for n > 0 {
		p--
		b[p] = byte('0' + n%10)
		n /= 10
	}
	return string(b[p:])
}

func Test036_BuildToolsInFinal(t *testing.T) {
	// Round-3 gap shape: final image reinstalls build/debug tools.
	expectFinding(t, buildToolsInFinal{}, stage(t, "FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y gcc git curl strace vim\n"), 1)
	expectFinding(t, buildToolsInFinal{}, stage(t, "FROM python:3.11.9-slim-bookworm\nRUN apt-get update && apt-get install -y curl git strace\n"), 1)
	expectFinding(t, buildToolsInFinal{}, stage(t, "FROM alpine:3.19\nRUN apk add --no-cache gdb make\n"), 1)
	expectFinding(t, buildToolsInFinal{}, stage(t, "FROM centos:8\nRUN yum install -y tcpdump\n"), 1)
	// curl/wget alone are not build tools (curl-pipe is rule 012).
	expectFinding(t, buildToolsInFinal{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\n"), 0)
	expectFinding(t, buildToolsInFinal{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y python3\n"), 0)
	// Removal verbs are not installs.
	expectFinding(t, buildToolsInFinal{}, stage(t, "FROM ubuntu:22.04\nRUN apt-get purge -y gcc && apt-get autoremove -y\n"), 0)
}

func Test036_BuildStageQuiet(t *testing.T) {
	// Tools in a build stage are legitimate; only the final stage fires.
	rs := multiStage(t, "FROM golang:1.22-bookworm AS build\nRUN apt-get update && apt-get install -y gcc git\nFROM gcr.io/distroless/static-debian12:nonroot\nCOPY --from=build /app/server /app/server\n")
	if len(rs) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(rs))
	}
	expectFinding(t, buildToolsInFinal{}, rs[0], 0)
	expectFinding(t, buildToolsInFinal{}, rs[1], 0)
}
