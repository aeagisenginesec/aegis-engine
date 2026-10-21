// Additional Dockerfile rules, AEGIS-DOCKER-011 and up.
//
// These rules extend the base pack (docker.go) with deeper container
// hygiene: build secrets, layer hygiene, image minimalism, runtime
// configuration (WORKDIR, STOPSIGNAL, SHELL), and package-manager best
// practices. All helpers follow the patterns in docker.go.
package docker

import (
	"regexp"
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// extraRules returns rules AEGIS-DOCKER-011 through AEGIS-DOCKER-037.
func extraRules() []ir.Rule {
	return []ir.Rule{
		argSecrets{},           // AEGIS-DOCKER-011
		curlPipeShell{},        // AEGIS-DOCKER-012
		runChown{},             // AEGIS-DOCKER-013
		chmod777{},             // AEGIS-DOCKER-014
		noWorkdir{},            // AEGIS-DOCKER-015
		deprecatedMaintainer{}, // AEGIS-DOCKER-016
		noMaintainerLabel{},    // AEGIS-DOCKER-017
		noStopsignal{},         // AEGIS-DOCKER-018
		onbuildUsed{},          // AEGIS-DOCKER-019
		volumeDeclared{},       // AEGIS-DOCKER-020
		sensitiveCopy{},        // AEGIS-DOCKER-021
		broadCopyContext{},     // AEGIS-DOCKER-022
		shellNoPipefail{},      // AEGIS-DOCKER-023
		shellFormCmd{},         // AEGIS-DOCKER-024
		singleStageBuild{},     // AEGIS-DOCKER-025
		fullOSBase{},           // AEGIS-DOCKER-026
		floatingMajorTag{},     // AEGIS-DOCKER-027
		privilegedPort{},       // AEGIS-DOCKER-028
		aptUnpinned{},          // AEGIS-DOCKER-029
		apkNoCache{},           // AEGIS-DOCKER-030
		yumNoClean{},           // AEGIS-DOCKER-031
		pipNoCacheDir{},        // AEGIS-DOCKER-032
		aptUpgrade{},           // AEGIS-DOCKER-033
		runSecrets{},           // AEGIS-DOCKER-034
		addRemoteURL{},         // AEGIS-DOCKER-035
		buildToolsInFinal{},    // AEGIS-DOCKER-036
		nopasswdSudoers{},      // AEGIS-DOCKER-037
	}
}

// getInt extracts an integer attribute stored as int or float64.
func getInt(r ir.Resource, name string) (int, ir.Span, bool, bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return 0, ir.Span{}, false, false
	}
	switch n := v.Raw.(type) {
	case int:
		return n, v.Span, true, v.Known
	case float64:
		return int(n), v.Span, true, v.Known
	}
	return 0, ir.Span{}, true, false
}

// getStrings returns a string list attribute as plain strings.
func getStrings(r ir.Resource, name string) ([]string, []ir.Span, bool, bool) {
	l, _, present, known := getList(r, name)
	if !present || !known {
		return nil, nil, present, known
	}
	var out []string
	var spans []ir.Span
	for _, v := range l {
		s, ok := v.AsString()
		if !ok {
			continue
		}
		out = append(out, s)
		spans = append(spans, v.Span)
	}
	return out, spans, true, true
}

// secretEntries extracts the {name, span} secret entries used by the
// arg_secrets / env_secrets attributes.
func secretEntries(r ir.Resource, name string) []ir.Value {
	l, _, present, known := getList(r, name)
	if !present || !known {
		return nil
	}
	return l
}

func secretName(v ir.Value) (string, ir.Span, bool) {
	m, ok := v.AsMap()
	if !ok {
		return "", ir.Span{}, false
	}
	nv, ok := m["name"]
	if !ok {
		return "", ir.Span{}, false
	}
	name, nok := nv.AsString()
	if !nok || strings.TrimSpace(name) == "" {
		return "", ir.Span{}, false
	}
	return name, nv.Span, true
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-011: secret in ARG default (high)
// ---------------------------------------------------------------------------

type argSecrets struct{}

func (argSecrets) ID() string { return "AEGIS-DOCKER-011" }
func (argSecrets) Title() string {
	return "Secret in ARG default value"
}
func (argSecrets) Description() string {
	return "ARG defaults with secret-looking names are baked into the " +
		"build cache and image history (docker history shows them). " +
		"Pass secrets with BuildKit --secret mounts and multi-stage " +
		"builds so they never land in a layer."
}
func (argSecrets) Severity() ir.Severity         { return ir.SeverityHigh }
func (argSecrets) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (argSecrets) Check(r ir.Resource) []ir.Finding {
	rule := argSecrets{}
	var out []ir.Finding
	for _, s := range secretEntries(r, "arg_secrets") {
		name, span, ok := secretName(s)
		if !ok {
			continue
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "ARG", span,
			name+"=[REDACTED]",
			"no secrets in ARG defaults; use BuildKit --secret mounts",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-012: curl/wget piped to shell (high)
// ---------------------------------------------------------------------------

type curlPipeShell struct{}

func (curlPipeShell) ID() string { return "AEGIS-DOCKER-012" }
func (curlPipeShell) Title() string {
	return "Remote script piped to shell"
}
func (curlPipeShell) Description() string {
	return "Piping curl/wget output straight into sh or bash executes " +
		"remote code with no integrity check: a compromised server or " +
		"MITM owns the build. Download the file, verify a checksum or " +
		"signature, then execute it."
}
func (curlPipeShell) Severity() ir.Severity         { return ir.SeverityHigh }
func (curlPipeShell) AppliesTo(resType string) bool { return appliesToDocker(resType) }

// pipeToShell matches `curl ... | sh`, `wget -qO- url | bash`, etc.
var pipeToShell = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;]*\|\s*(sh|bash|dash)\b`)

func (curlPipeShell) Check(r ir.Resource) []ir.Finding {
	rule := curlPipeShell{}
	var out []ir.Finding
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		if pipeToShell.MatchString(cmd) {
			out = append(out, finding(
				rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
				r, "RUN", c.Span, "curl/wget piped to shell",
				"download, verify checksum/signature, then execute",
			))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-013: chown in RUN instead of COPY --chown (low)
// ---------------------------------------------------------------------------

type runChown struct{}

func (runChown) ID() string { return "AEGIS-DOCKER-013" }
func (runChown) Title() string {
	return "chown in RUN instead of COPY --chown"
}
func (runChown) Description() string {
	return "Running chown in a separate RUN duplicates every affected " +
		"file into a new layer, bloating the image. Use COPY --chown to " +
		"set ownership at copy time."
}
func (runChown) Severity() ir.Severity         { return ir.SeverityLow }
func (runChown) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (runChown) Check(r ir.Resource) []ir.Finding {
	rule := runChown{}
	chownUsed, _, present, known := getBool(r, "copy_chown_used")
	if present && known && chownUsed {
		return nil
	}
	var out []ir.Finding
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		if hasChown(cmd) {
			out = append(out, finding(
				rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
				r, "RUN", c.Span, "chown in RUN layer",
				"COPY --chown=<user>:<group>",
			))
		}
	}
	return out
}

// hasChown reports whether a RUN command invokes chown as a command.
func hasChown(cmd string) bool {
	for _, seg := range strings.FieldsFunc(cmd, func(r rune) bool {
		return r == ';' || r == '&' || r == '|' || r == '\n'
	}) {
		for _, tok := range strings.Fields(seg) {
			if strings.Trim(tok, "()") == "chown" {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-014: chmod 777 in RUN (medium)
// ---------------------------------------------------------------------------

type chmod777 struct{}

func (chmod777) ID() string { return "AEGIS-DOCKER-014" }
func (chmod777) Title() string {
	return "Overly permissive chmod in build"
}
func (chmod777) Description() string {
	return "chmod 777 (or a+rwx) makes files world-writable: any " +
		"compromised process in the container can modify them. Grant " +
		"the least privilege the application needs."
}
func (chmod777) Severity() ir.Severity         { return ir.SeverityMedium }
func (chmod777) AppliesTo(resType string) bool { return appliesToDocker(resType) }

var chmodPermissive = regexp.MustCompile(`(?i)\bchmod\b[^;&|]*\s(a\+rwx|7777?|0777?)\b`)

func (chmod777) Check(r ir.Resource) []ir.Finding {
	rule := chmod777{}
	var out []ir.Finding
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		if chmodPermissive.MatchString(cmd) {
			out = append(out, finding(
				rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
				r, "RUN", c.Span, "world-writable permissions via chmod",
				"least-privilege permissions (e.g. 755/644)",
			))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-015: no WORKDIR (low)
// ---------------------------------------------------------------------------

type noWorkdir struct{}

func (noWorkdir) ID() string { return "AEGIS-DOCKER-015" }
func (noWorkdir) Title() string {
	return "No WORKDIR directive"
}
func (noWorkdir) Description() string {
	return "Without WORKDIR the build and the container run from /, so " +
		"relative paths and stray files land in the filesystem root. " +
		"Set an explicit WORKDIR for the application."
}
func (noWorkdir) Severity() ir.Severity         { return ir.SeverityLow }
func (noWorkdir) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (noWorkdir) Check(r ir.Resource) []ir.Finding {
	rule := noWorkdir{}
	wd, _, present, known := getString(r, "workdir")
	if present && !known {
		return nil
	}
	if present && strings.TrimSpace(wd) != "" {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "WORKDIR", r.Span, "absent (defaults to /)",
		"WORKDIR /app (or similar)",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-016: deprecated MAINTAINER (low)
// ---------------------------------------------------------------------------

type deprecatedMaintainer struct{}

func (deprecatedMaintainer) ID() string { return "AEGIS-DOCKER-016" }
func (deprecatedMaintainer) Title() string {
	return "Deprecated MAINTAINER instruction"
}
func (deprecatedMaintainer) Description() string {
	return "MAINTAINER is deprecated and ignored by modern tooling. " +
		"Use LABEL maintainer=... or org.opencontainers.image.authors instead."
}
func (deprecatedMaintainer) Severity() ir.Severity         { return ir.SeverityLow }
func (deprecatedMaintainer) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (deprecatedMaintainer) Check(r ir.Resource) []ir.Finding {
	rule := deprecatedMaintainer{}
	used, _, present, known := getBool(r, "uses_maintainer")
	if !present || !known || !used {
		return nil
	}
	span := r.Span
	if v, ok := r.Attributes["maintainer_span"]; ok {
		span = v.Span
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "MAINTAINER", span, "deprecated MAINTAINER instruction",
		"LABEL maintainer=... / org.opencontainers.image.authors",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-017: no maintainer label (low)
// ---------------------------------------------------------------------------

type noMaintainerLabel struct{}

func (noMaintainerLabel) ID() string { return "AEGIS-DOCKER-017" }
func (noMaintainerLabel) Title() string {
	return "No maintainer label"
}
func (noMaintainerLabel) Description() string {
	return "Images without ownership metadata are harder to triage when " +
		"a vulnerability is found. Add LABEL maintainer= or " +
		"org.opencontainers.image.authors."
}
func (noMaintainerLabel) Severity() ir.Severity         { return ir.SeverityLow }
func (noMaintainerLabel) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (noMaintainerLabel) Check(r ir.Resource) []ir.Finding {
	rule := noMaintainerLabel{}
	// Image metadata exists only on the image that ships. A build
	// stage's labels are discarded with the stage, so flagging them
	// is a false positive (Sprint 2). Same gate as noNonRootUser /
	// buildToolsInFinal; absent is_final_stage still judges.
	if fin, _, present, known := getBool(r, "is_final_stage"); present && known && !fin {
		return nil
	}
	labels, _, present, known := getStrings(r, "labels")
	if present && !known {
		return nil
	}
	for _, l := range labels {
		ll := strings.ToLower(l)
		if ll == "maintainer" || ll == "org.opencontainers.image.authors" {
			return nil
		}
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "LABEL", r.Span, "no maintainer/authors label",
		"LABEL maintainer=... or org.opencontainers.image.authors=...",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-018: no STOPSIGNAL (low)
// ---------------------------------------------------------------------------

type noStopsignal struct{}

func (noStopsignal) ID() string { return "AEGIS-DOCKER-018" }
func (noStopsignal) Title() string {
	return "No STOPSIGNAL directive"
}
func (noStopsignal) Description() string {
	return "Without STOPSIGNAL the container gets SIGTERM, which apps " +
		"that only handle SIGINT (or expect another signal) ignore " +
		"until the orchestrator SIGKILLs them, risking data loss. " +
		"Declare the signal your app handles for graceful shutdown."
}
func (noStopsignal) Severity() ir.Severity         { return ir.SeverityLow }
func (noStopsignal) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (noStopsignal) Check(r ir.Resource) []ir.Finding {
	rule := noStopsignal{}
	// STOPSIGNAL is image config: only the final stage's value reaches
	// the shipped image. A build stage without one cannot affect how
	// the container is stopped (Sprint 2). Absent is_final_stage
	// still judges.
	if fin, _, present, known := getBool(r, "is_final_stage"); present && known && !fin {
		return nil
	}
	set, _, present, known := getBool(r, "has_stopsignal")
	if present && !known {
		return nil
	}
	if present && set {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "STOPSIGNAL", r.Span, "absent",
		"STOPSIGNAL <signal your app handles>",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-019: ONBUILD triggers (low)
// ---------------------------------------------------------------------------

type onbuildUsed struct{}

func (onbuildUsed) ID() string { return "AEGIS-DOCKER-019" }
func (onbuildUsed) Title() string {
	return "ONBUILD triggers present"
}
func (onbuildUsed) Description() string {
	return "ONBUILD instructions execute implicitly in every downstream " +
		"image, running code the downstream author never reviewed. " +
		"Prefer explicit build steps in the child Dockerfile."
}
func (onbuildUsed) Severity() ir.Severity         { return ir.SeverityLow }
func (onbuildUsed) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (onbuildUsed) Check(r ir.Resource) []ir.Finding {
	rule := onbuildUsed{}
	used, _, present, known := getBool(r, "uses_onbuild")
	if !present || !known || !used {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "ONBUILD", r.Span, "ONBUILD trigger present",
		"explicit instructions in downstream Dockerfiles",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-020: VOLUME declared (low)
// ---------------------------------------------------------------------------

type volumeDeclared struct{}

func (volumeDeclared) ID() string { return "AEGIS-DOCKER-020" }
func (volumeDeclared) Title() string {
	return "VOLUME declared in image"
}
func (volumeDeclared) Description() string {
	return "VOLUME creates anonymous volumes at runtime that outlive " +
		"the container and silently persist data (and discard later " +
		"image changes to that path). Declare volumes at deploy time " +
		"instead of baking them into the image."
}
func (volumeDeclared) Severity() ir.Severity         { return ir.SeverityLow }
func (volumeDeclared) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (volumeDeclared) Check(r ir.Resource) []ir.Finding {
	rule := volumeDeclared{}
	used, _, present, known := getBool(r, "uses_volume")
	if !present || !known || !used {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "VOLUME", r.Span, "VOLUME declared",
		"declare volumes at deploy time, not in the image",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-021: sensitive files copied into image (high)
// ---------------------------------------------------------------------------

type sensitiveCopy struct{}

func (sensitiveCopy) ID() string { return "AEGIS-DOCKER-021" }
func (sensitiveCopy) Title() string {
	return "Sensitive file copied into image"
}
func (sensitiveCopy) Description() string {
	return "COPYing VCS metadata, dotenv files, or private keys bakes " +
		"them into image layers where anyone with the image can read " +
		"them. Exclude them with .dockerignore and never COPY secrets."
}
func (sensitiveCopy) Severity() ir.Severity         { return ir.SeverityHigh }
func (sensitiveCopy) AppliesTo(resType string) bool { return appliesToDocker(resType) }

// sensitiveCopyNames are exact path segments that must never be copied.
var sensitiveCopyNames = map[string]bool{
	".git": true, ".env": true, ".ssh": true, ".aws": true,
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
	"credentials": true, ".gnupg": true, ".pki": true,
}

func isSensitiveCopySrc(src string) bool {
	s := strings.Trim(src, `"'`)
	// Multi-stage copy sources (--from) are stage artifacts, not context.
	if s == "" {
		return false
	}
	parts := strings.Split(s, "/")
	for _, p := range parts {
		if sensitiveCopyNames[p] {
			return true
		}
		// .env.<suffix> variants (e.g. .env.production).
		if strings.HasPrefix(p, ".env.") {
			return true
		}
		lp := strings.ToLower(p)
		if strings.HasSuffix(lp, ".pem") || strings.HasSuffix(lp, ".key") {
			return true
		}
	}
	return false
}

func (sensitiveCopy) Check(r ir.Resource) []ir.Finding {
	rule := sensitiveCopy{}
	srcs, spans, present, known := getStrings(r, "copy_sources")
	if !present || !known {
		return nil
	}
	var out []ir.Finding
	for i, s := range srcs {
		if !isSensitiveCopySrc(s) {
			continue
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "COPY", spans[i], "copies "+s,
			"exclude via .dockerignore; never COPY secrets into layers",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-022: COPY of entire build context (low)
// ---------------------------------------------------------------------------

type broadCopyContext struct{}

func (broadCopyContext) ID() string { return "AEGIS-DOCKER-022" }
func (broadCopyContext) Title() string {
	return "COPY of entire build context"
}
func (broadCopyContext) Description() string {
	return "COPY . ships the whole build context into the image, often " +
		"including credentials, VCS history, and dev tooling. Copy " +
		"only what the app needs and gate the context with .dockerignore."
}
func (broadCopyContext) Severity() ir.Severity         { return ir.SeverityLow }
func (broadCopyContext) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (broadCopyContext) Check(r ir.Resource) []ir.Finding {
	rule := broadCopyContext{}
	srcs, spans, present, known := getStrings(r, "copy_sources")
	if !present || !known {
		return nil
	}
	var out []ir.Finding
	for i, s := range srcs {
		t := strings.Trim(strings.Trim(s, `"'`), "./")
		if t == "" || t == "*" {
			out = append(out, finding(
				rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
				r, "COPY", spans[i], "COPY "+s+" (entire context)",
				"COPY only required paths; maintain .dockerignore",
			))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-023: SHELL without pipefail (low)
// ---------------------------------------------------------------------------

type shellNoPipefail struct{}

func (shellNoPipefail) ID() string { return "AEGIS-DOCKER-023" }
func (shellNoPipefail) Title() string {
	return "SHELL without pipefail"
}
func (shellNoPipefail) Description() string {
	return "Without pipefail a failing command in a pipeline is masked " +
		"by the exit status of the last command, so broken builds look " +
		"green. Add -o pipefail to SHELL (e.g. SHELL " +
		"[\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"])."
}
func (shellNoPipefail) Severity() ir.Severity         { return ir.SeverityLow }
func (shellNoPipefail) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (shellNoPipefail) Check(r ir.Resource) []ir.Finding {
	rule := shellNoPipefail{}
	sh, shspan, present, known := getString(r, "shell")
	if !present || !known || strings.TrimSpace(sh) == "" {
		return nil
	}
	if !isUnixShell(sh) || strings.Contains(sh, "pipefail") {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "SHELL", shspan, sh,
		`SHELL ["/bin/bash", "-o", "pipefail", "-c"]`,
	)}
}

// isUnixShell reports whether a SHELL instruction targets a POSIX-style
// shell (sh, bash, dash, ash, zsh), where pipefail is meaningful.
func isUnixShell(sh string) bool {
	for _, tok := range strings.FieldsFunc(strings.ToLower(sh), func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == '[' || r == ']' || r == '"' || r == '\''
	}) {
		base := tok
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		if base == "sh" || strings.HasSuffix(base, "sh") && base != "powershell" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-024: CMD/ENTRYPOINT in shell form (low)
// ---------------------------------------------------------------------------

type shellFormCmd struct{}

func (shellFormCmd) ID() string { return "AEGIS-DOCKER-024" }
func (shellFormCmd) Title() string {
	return "CMD/ENTRYPOINT in shell form"
}
func (shellFormCmd) Description() string {
	return "Shell-form CMD/ENTRYPOINT runs under /bin/sh -c, so signals " +
		"don't reach the app (PID 1 is the shell) and graceful shutdown " +
		"breaks. Use the exec form: CMD [\"app\", \"--flag\"]."
}
func (shellFormCmd) Severity() ir.Severity         { return ir.SeverityLow }
func (shellFormCmd) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (shellFormCmd) Check(r ir.Resource) []ir.Finding {
	rule := shellFormCmd{}
	var out []ir.Finding
	for _, attr := range []string{"cmd_shell_form", "entrypoint_shell_form"} {
		v, _, present, known := getBool(r, attr)
		if !present || !known || !v {
			continue
		}
		inst := "CMD"
		if attr == "entrypoint_shell_form" {
			inst = "ENTRYPOINT"
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, inst, r.Span, inst+" in shell form",
			inst+` ["executable", "arg"] (exec form)`,
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-025: single-stage build from toolchain image (low)
// ---------------------------------------------------------------------------

type singleStageBuild struct{}

func (singleStageBuild) ID() string { return "AEGIS-DOCKER-025" }
func (singleStageBuild) Title() string {
	return "Build toolchain shipped in final image"
}
func (singleStageBuild) Description() string {
	return "The final image is built FROM a compiler/toolchain image " +
		"with no multi-stage split, so compilers, package managers, and " +
		"build caches ship to production. Use a multi-stage build and " +
		"COPY only the artifact into a minimal runtime image."
}
func (singleStageBuild) Severity() ir.Severity         { return ir.SeverityLow }
func (singleStageBuild) AppliesTo(resType string) bool { return appliesToDocker(resType) }

// toolchainImages are base images whose whole purpose is compiling.
var toolchainImages = map[string]bool{
	"golang": true, "rust": true, "node": true, "maven": true,
	"gradle": true, "openjdk": true, "gcc": true, "clang": true,
	"swift": true, "temurin": true, "corretto": true, "sdk": true,
	"dotnet-sdk": true,
}

func (singleStageBuild) Check(r ir.Resource) []ir.Finding {
	rule := singleStageBuild{}
	total, _, present, known := getInt(r, "total_stages")
	if !present || !known || total != 1 {
		return nil
	}
	img, ispan, ipresent, iknown := getString(r, "base_image")
	if !ipresent || !iknown || strings.TrimSpace(img) == "" {
		return nil
	}
	if strings.Contains(img, "@sha256:") {
		return nil
	}
	_, rest := splitRegistry(strings.TrimSpace(img))
	last := rest
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		last = rest[i+1:]
	}
	if !toolchainImages[strings.ToLower(last)] {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "base_image", ispan, img,
		"multi-stage build with a minimal runtime final image",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-026: full OS base image (low)
// ---------------------------------------------------------------------------

type fullOSBase struct{}

func (fullOSBase) ID() string { return "AEGIS-DOCKER-026" }
func (fullOSBase) Title() string {
	return "Full OS base image"
}
func (fullOSBase) Description() string {
	return "Full Linux distributions carry hundreds of packages the app " +
		"never uses, each a potential CVE. Prefer minimal bases " +
		"(distroless, Chainguard, Alpine, or -slim variants)."
}
func (fullOSBase) Severity() ir.Severity         { return ir.SeverityLow }
func (fullOSBase) AppliesTo(resType string) bool { return appliesToDocker(resType) }

var fullOSImages = map[string]bool{
	"ubuntu": true, "debian": true, "centos": true, "fedora": true,
	"rockylinux": true, "almalinux": true, "amazonlinux": true,
	"opensuse": true, "oraclelinux": true, "rhel": true, "ubi": true,
}

var minimalMarkers = []string{
	"distroless", "alpine", "slim", "chainguard", "wolfi", "busybox", "scratch", "static",
}

func (fullOSBase) Check(r ir.Resource) []ir.Finding {
	rule := fullOSBase{}
	img, ispan, present, known := getString(r, "base_image")
	if !present || !known || strings.TrimSpace(img) == "" {
		return nil
	}
	img = strings.TrimSpace(img)
	if strings.Contains(img, "@sha256:") {
		return nil
	}
	lower := strings.ToLower(img)
	for _, m := range minimalMarkers {
		if strings.Contains(lower, m) {
			return nil
		}
	}
	_, rest := splitRegistry(img)
	last := rest
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		last = rest[i+1:]
	}
	// Strip any tag for the name check.
	if i := strings.LastIndex(last, ":"); i >= 0 {
		last = last[:i]
	}
	if !fullOSImages[strings.ToLower(last)] {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "base_image", ispan, img,
		"minimal base (distroless, Chainguard, Alpine, -slim)",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-027: floating major-only tag (low)
// ---------------------------------------------------------------------------

type floatingMajorTag struct{}

func (floatingMajorTag) ID() string { return "AEGIS-DOCKER-027" }
func (floatingMajorTag) Title() string {
	return "Base image uses floating major-only tag"
}
func (floatingMajorTag) Description() string {
	return "Tags like python:3 or node:20 float across minor and patch " +
		"releases, so rebuilds silently change the runtime. Pin the " +
		"full version (e.g. python:3.12.1) or a digest."
}
func (floatingMajorTag) Severity() ir.Severity         { return ir.SeverityLow }
func (floatingMajorTag) AppliesTo(resType string) bool { return appliesToDocker(resType) }

var majorOnlyTag = regexp.MustCompile(`^\d+$`)

func (floatingMajorTag) Check(r ir.Resource) []ir.Finding {
	rule := floatingMajorTag{}
	img, ispan, ipresent, iknown := getString(r, "base_image")
	if !ipresent || !iknown || strings.TrimSpace(img) == "" {
		return nil
	}
	if strings.Contains(img, "@sha256:") {
		return nil
	}
	tag, _, tpresent, tknown := getString(r, "base_tag")
	if tpresent && !tknown {
		return nil
	}
	if !tpresent || !majorOnlyTag.MatchString(strings.TrimSpace(tag)) {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "base_image", ispan, img,
		"fully pinned version tag (e.g. python:3.12.1) or digest",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-028: privileged port exposed (medium)
// ---------------------------------------------------------------------------

type privilegedPort struct{}

func (privilegedPort) ID() string { return "AEGIS-DOCKER-028" }
func (privilegedPort) Title() string {
	return "Privileged port exposed"
}
func (privilegedPort) Description() string {
	return "Binding a port below 1024 requires root (or " +
		"CAP_NET_BIND_SERVICE) at runtime, which conflicts with " +
		"running as a non-root user. Expose only unprivileged ports " +
		"(or the standard 80/443) and remap at deploy time."
}
func (privilegedPort) Severity() ir.Severity         { return ir.SeverityMedium }
func (privilegedPort) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (privilegedPort) Check(r ir.Resource) []ir.Finding {
	rule := privilegedPort{}
	ports, _, present, known := getList(r, "exposed_ports")
	if !present || !known {
		return nil
	}
	var out []ir.Finding
	for _, p := range ports {
		s, ok := p.AsString()
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n >= 1024 || n == 80 || n == 443 || n == 22 {
			continue // 22 is covered by AEGIS-DOCKER-006
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "EXPOSE", p.Span, s,
			"unprivileged port (>= 1024); remap at deploy time",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-029: apt-get install without pinned versions (low)
// ---------------------------------------------------------------------------

type aptUnpinned struct{}

func (aptUnpinned) ID() string { return "AEGIS-DOCKER-029" }
func (aptUnpinned) Title() string {
	return "apt-get install without pinned versions"
}
func (aptUnpinned) Description() string {
	return "Unpinned apt packages float across rebuilds, making images " +
		"non-reproducible and silently pulling new versions. Pin " +
		"versions: apt-get install pkg=1.2.3."
}
func (aptUnpinned) Severity() ir.Severity         { return ir.SeverityLow }
func (aptUnpinned) AppliesTo(resType string) bool { return appliesToDocker(resType) }

// aptInstallPkgs extracts package tokens from apt-get/apt install segments.
func aptInstallPkgs(cmd string) []string {
	var out []string
	lower := strings.ToLower(cmd)
	for _, seg := range strings.FieldsFunc(lower, func(r rune) bool {
		return r == ';' || r == '&' || r == '|' || r == '\n'
	}) {
		toks := strings.Fields(seg)
		for i := 0; i < len(toks); i++ {
			if toks[i] != "apt-get" && toks[i] != "apt" {
				continue
			}
			j := i + 1
			if j < len(toks) && toks[j] == "install" {
				j++
			} else {
				continue
			}
			for ; j < len(toks) && toks[j] != "apt-get" && toks[j] != "apt"; j++ {
				t := toks[j]
				if strings.HasPrefix(t, "-") || t == "" {
					continue
				}
				out = append(out, t)
			}
		}
	}
	return out
}

func (aptUnpinned) Check(r ir.Resource) []ir.Finding {
	rule := aptUnpinned{}
	var out []ir.Finding
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		var unpinned []string
		for _, p := range aptInstallPkgs(cmd) {
			if strings.Contains(p, "=") || strings.Contains(p, "$") {
				continue
			}
			unpinned = append(unpinned, p)
		}
		if len(unpinned) > 0 {
			out = append(out, finding(
				rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
				r, "RUN", c.Span, "unpinned packages: "+strings.Join(unpinned, ", "),
				"apt-get install pkg=<version>",
			))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-030: apk add without --no-cache (low)
// ---------------------------------------------------------------------------

type apkNoCache struct{}

func (apkNoCache) ID() string { return "AEGIS-DOCKER-030" }
func (apkNoCache) Title() string {
	return "apk add without --no-cache"
}
func (apkNoCache) Description() string {
	return "apk add caches the package index in the image layer. Pass " +
		"--no-cache to keep Alpine layers lean."
}
func (apkNoCache) Severity() ir.Severity         { return ir.SeverityLow }
func (apkNoCache) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (apkNoCache) Check(r ir.Resource) []ir.Finding {
	rule := apkNoCache{}
	var out []ir.Finding
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		lower := strings.ToLower(cmd)
		if !strings.Contains(lower, "apk add") {
			continue
		}
		if strings.Contains(lower, "--no-cache") {
			continue
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "RUN", c.Span, "apk add without --no-cache",
			"apk add --no-cache",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-031: yum/dnf install without cache cleanup (low)
// ---------------------------------------------------------------------------

type yumNoClean struct{}

func (yumNoClean) ID() string { return "AEGIS-DOCKER-031" }
func (yumNoClean) Title() string {
	return "yum/dnf install without cache cleanup"
}
func (yumNoClean) Description() string {
	return "yum/dnf leaves package caches in the image layer. Run " +
		"yum clean all (or dnf clean all) in the same RUN."
}
func (yumNoClean) Severity() ir.Severity         { return ir.SeverityLow }
func (yumNoClean) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (yumNoClean) Check(r ir.Resource) []ir.Finding {
	rule := yumNoClean{}
	var out []ir.Finding
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		lower := strings.ToLower(cmd)
		if !strings.Contains(lower, "yum install") && !strings.Contains(lower, "dnf install") {
			continue
		}
		if strings.Contains(lower, "clean all") {
			continue
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "RUN", c.Span, "yum/dnf install without clean all",
			"yum clean all / dnf clean all in the same RUN",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-032: pip install without --no-cache-dir (low)
// ---------------------------------------------------------------------------

type pipNoCacheDir struct{}

func (pipNoCacheDir) ID() string { return "AEGIS-DOCKER-032" }
func (pipNoCacheDir) Title() string {
	return "pip install without --no-cache-dir"
}
func (pipNoCacheDir) Description() string {
	return "pip caches downloaded wheels in ~/.cache/pip, bloating the " +
		"image layer. Pass --no-cache-dir to pip install."
}
func (pipNoCacheDir) Severity() ir.Severity         { return ir.SeverityLow }
func (pipNoCacheDir) AppliesTo(resType string) bool { return appliesToDocker(resType) }

var pipInstall = regexp.MustCompile(`(?i)\bpip3?\b[^;&|]*\binstall\b`)

func (pipNoCacheDir) Check(r ir.Resource) []ir.Finding {
	rule := pipNoCacheDir{}
	var out []ir.Finding
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		if !pipInstall.MatchString(cmd) {
			continue
		}
		if strings.Contains(strings.ToLower(cmd), "--no-cache-dir") {
			continue
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "RUN", c.Span, "pip install without --no-cache-dir",
			"pip install --no-cache-dir",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-033: apt-get upgrade in build (low)
// ---------------------------------------------------------------------------

type aptUpgrade struct{}

func (aptUpgrade) ID() string { return "AEGIS-DOCKER-033" }
func (aptUpgrade) Title() string {
	return "apt-get upgrade in image build"
}
func (aptUpgrade) Description() string {
	return "apt-get upgrade pulls whatever is newest at build time, " +
		"making images non-reproducible and bloating layers. Base " +
		"images already carry security updates; pin what you install " +
		"instead of upgrading everything."
}
func (aptUpgrade) Severity() ir.Severity         { return ir.SeverityLow }
func (aptUpgrade) AppliesTo(resType string) bool { return appliesToDocker(resType) }

var aptUpgradeRe = regexp.MustCompile(`(?i)\bapt(-get)?\s+(dist-)?upgrade\b`)

func (aptUpgrade) Check(r ir.Resource) []ir.Finding {
	rule := aptUpgrade{}
	var out []ir.Finding
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		if aptUpgradeRe.MatchString(cmd) {
			out = append(out, finding(
				rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
				r, "RUN", c.Span, "apt-get upgrade in build",
				"rely on updated base images; pin installed versions",
			))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-034: credentials embedded in RUN (high)
// ---------------------------------------------------------------------------

type runSecrets struct{}

func (runSecrets) ID() string { return "AEGIS-DOCKER-034" }
func (runSecrets) Title() string {
	return "Credentials embedded in RUN layer"
}
func (runSecrets) Description() string {
	return "Credentials baked into a RUN command persist in the image " +
		"layer and build cache, readable via docker history or layer " +
		"inspection. Inject secrets at runtime or via BuildKit --secret " +
		"mounts in a multi-stage build. Values are never shown."
}
func (runSecrets) Severity() ir.Severity         { return ir.SeverityHigh }
func (runSecrets) AppliesTo(resType string) bool { return appliesToDocker(resType) }

// urlWithCreds matches userinfo in URLs: https://user:pass@host.
var urlWithCreds = regexp.MustCompile(`://[^/\s:@?#]+:[^/\s@?#]+@`)

// curlUserCreds matches curl/wget -u|--user user:pass.
var curlUserCreds = regexp.MustCompile(`(?i)(?:^|\s)(?:-u|--user)\s+['"]?[^\s'":]+:[^\s'"]+`)

// secretAssignment matches NAME=value with secret-looking names and a
// literal value (no $ expansion). The name may be prefixed (DB_PASSWORD),
// so the leading boundary is "not a letter" rather than \b.
var secretAssignment = regexp.MustCompile(`(?i)(?:^|[^a-zA-Z])(passw(or)?d|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"]?([^'"\s$][^'"\s]*)`)

func (runSecrets) Check(r ir.Resource) []ir.Finding {
	rule := runSecrets{}
	var out []ir.Finding
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		actual := ""
		switch {
		case urlWithCreds.MatchString(cmd):
			actual = "credentials in URL userinfo ([REDACTED])"
		case curlUserCreds.MatchString(cmd):
			actual = "credentials via curl -u/--user ([REDACTED])"
		case secretAssignment.MatchString(cmd):
			m := secretAssignment.FindStringSubmatch(cmd)
			name := ""
			if len(m) > 1 {
				name = strings.ToUpper(m[1])
			}
			actual = name + "=[REDACTED] in RUN"
		default:
			continue
		}
		out = append(out, finding(
			rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
			r, "RUN", c.Span, actual,
			"runtime injection or BuildKit --secret mounts",
		))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-035: ADD fetches remote URL (medium)
// ---------------------------------------------------------------------------

type addRemoteURL struct{}

func (addRemoteURL) ID() string { return "AEGIS-DOCKER-035" }
func (addRemoteURL) Title() string {
	return "ADD fetches remote URL"
}
func (addRemoteURL) Description() string {
	return "ADD with a remote URL downloads at build time with no " +
		"integrity verification, and the layer is never invalidated " +
		"properly. Use curl/wget with a checksum verification followed " +
		"by COPY instead."
}
func (addRemoteURL) Severity() ir.Severity         { return ir.SeverityMedium }
func (addRemoteURL) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (addRemoteURL) Check(r ir.Resource) []ir.Finding {
	rule := addRemoteURL{}
	remote, _, present, known := getBool(r, "add_remote")
	if !present || !known || !remote {
		return nil
	}
	span := r.Span
	if v, ok := r.Attributes["add_span"]; ok {
		span = v.Span
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "ADD", span, "ADD fetches remote URL",
		"curl/wget + checksum verification, then COPY",
	)}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-036: build tools installed in final image (high)
// ---------------------------------------------------------------------------

type buildToolsInFinal struct{}

func (buildToolsInFinal) ID() string { return "AEGIS-DOCKER-036" }
func (buildToolsInFinal) Title() string {
	return "Build tools installed in final image"
}
func (buildToolsInFinal) Description() string {
	return "Compilers, debuggers, and version-control clients installed " +
		"in the final (shipped) image let an attacker who gains code " +
		"execution compile exploits, inspect memory, or exfiltrate " +
		"through tooling the application never needs. Install build " +
		"tools in a build stage only and COPY the artifact into a " +
		"minimal runtime image. Only the final stage is judged: build " +
		"stages legitimately install toolchains."
}
func (buildToolsInFinal) Severity() ir.Severity         { return ir.SeverityHigh }
func (buildToolsInFinal) AppliesTo(resType string) bool { return appliesToDocker(resType) }

// buildToolPackages are package names that indicate a compiler,
// debugger, VCS client, or interactive diagnostic tool. curl/wget
// are deliberately NOT in this set: fetching tools alone are the
// curl-pipe-shell concern (012), and flagging every image that
// installs curl would re-create the build-tools false-positive
// class on images like the curl-pipe fixture.
var buildToolPackages = map[string]bool{
	"gcc": true, "g++": true, "cc": true, "clang": true, "tcc": true,
	"make": true, "cmake": true, "autoconf": true, "automake": true,
	"libtool": true, "pkg-config": true, "build-essential": true,
	"git": true, "git-lfs": true, "subversion": true, "svn": true,
	"mercurial": true, "hg": true, "cvs": true, "bazaar": true,
	"strace": true, "ltrace": true, "gdb": true, "lldb": true,
	"valgrind": true, "vim": true, "nano": true, "emacs": true,
	"netcat": true, "nc": true, "ncat": true, "nmap": true,
	"tcpdump": true, "wireshark": true, "tshark": true, "socat": true,
	"binutils": true, "bison": true, "flex": true,
	"python3-dev": true, "python-dev": true, "perl": true,
}

func (buildToolsInFinal) Check(r ir.Resource) []ir.Finding {
	rule := buildToolsInFinal{}
	// Only the final stage ships; build stages legitimately install
	// toolchains. (Absent is_final_stage: pre-existing hand-built
	// resources default to judged, as before.)
	if fin, _, present, known := getBool(r, "is_final_stage"); present && known && !fin {
		return nil
	}
	found := map[string]bool{}
	var span ir.Span
	for _, c := range runCommands(r) {
		cmd, ok := c.AsString()
		if !ok {
			continue
		}
		for _, tool := range installedBuildTools(cmd) {
			if !found[tool] {
				found[tool] = true
				span = c.Span
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	tools := make([]string, 0, len(found))
	for t := range found {
		tools = append(tools, t)
	}
	sortStrings(tools)
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "RUN", span,
		"build/debugging tools installed: "+strings.Join(tools, ", "),
		"install build tools in a build stage only; ship a minimal runtime image",
	)}
}

// installedBuildTools extracts build-tool package names installed by one
// RUN command across the common package managers (apt, apk, yum/dnf,
// zypper). Only install/add verbs are considered; removals, updates,
// and other verbs are ignored.
func installedBuildTools(cmd string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(tok string) {
		// Strip version pins (gcc=4:12.2) and arch qualifiers (gcc:amd64).
		if i := strings.IndexAny(tok, "=:"); i >= 0 {
			tok = tok[:i]
		}
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == "" || seen[tok] {
			return
		}
		if buildToolPackages[tok] || versionedCompiler(tok) {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	for _, seg := range strings.FieldsFunc(cmd, func(r rune) bool {
		return r == ';' || r == '&' || r == '|' || r == '\n'
	}) {
		toks := strings.Fields(seg)
		for i := 0; i < len(toks); i++ {
			var verbIdx int
			switch toks[i] {
			case "apt-get", "apt":
				verbIdx = i + 1
			case "apk":
				verbIdx = i + 1
			case "yum", "dnf", "microdnf", "zypper":
				verbIdx = i + 1
			default:
				continue
			}
			if verbIdx >= len(toks) {
				continue
			}
			verb := toks[verbIdx]
			isInstall := verb == "install" || verb == "add" || verb == "in"
			if toks[i] == "apk" && verb != "add" {
				isInstall = false
			}
			if toks[i] == "zypper" && verb != "install" && verb != "in" {
				isInstall = false
			}
			if !isInstall {
				continue
			}
			for j := verbIdx + 1; j < len(toks); j++ {
				t := toks[j]
				if strings.HasPrefix(t, "-") {
					continue // flags (and their =values) are not packages
				}
				add(t)
			}
		}
	}
	return out
}

// versionedCompiler matches versioned compiler packages such as gcc-12,
// g++-11, or clang-17.
func versionedCompiler(tok string) bool {
	for _, prefix := range []string{"gcc-", "g++-", "clang-"} {
		if !strings.HasPrefix(tok, prefix) {
			continue
		}
		rest := strings.TrimPrefix(tok, prefix)
		if rest == "" {
			return false
		}
		for _, r := range rest {
			if (r < '0' || r > '9') && r != '.' {
				return false
			}
		}
		return true
	}
	return false
}

// sortStrings sorts in place (small helper to avoid importing sort for
// one call site).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-DOCKER-037: passwordless sudo configured (NOPASSWD)
// ---------------------------------------------------------------------------

type nopasswdSudoers struct{}

func (nopasswdSudoers) ID() string { return "AEGIS-DOCKER-037" }
func (nopasswdSudoers) Title() string {
	return "Passwordless sudo configured (NOPASSWD)"
}
func (nopasswdSudoers) Description() string {
	return "A RUN step writes a NOPASSWD entry to /etc/sudoers (or " +
		"/etc/sudoers.d/), granting a user passwordless root. Any " +
		"process running as that user — including a compromised " +
		"application — can escalate to root without a password. " +
		"Require a password for sudo, or drop sudo entirely and rely " +
		"on USER for runtime privilege separation."
}
func (nopasswdSudoers) Severity() ir.Severity         { return ir.SeverityHigh }
func (nopasswdSudoers) AppliesTo(resType string) bool { return appliesToDocker(resType) }

func (nopasswdSudoers) Check(r ir.Resource) []ir.Finding {
	rule := nopasswdSudoers{}
	set, _, present, known := getBool(r, "nopasswd_sudoers")
	if !present || !known || !set {
		return nil
	}
	return []ir.Finding{finding(
		rule.ID(), rule.Title(), rule.Description(), rule.Severity(),
		r, "RUN", r.Span, "NOPASSWD entry written to a sudoers file",
		"no passwordless sudo entry in sudoers",
	)}
}
