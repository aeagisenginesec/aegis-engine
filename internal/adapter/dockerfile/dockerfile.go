// Package dockerfile implements ir.Adapter for Dockerfiles.
//
// Each build stage becomes one ir.Resource of type "docker_stage" named
// after the stage (FROM ... AS name) or stage<N> when unnamed. Attributes:
//   - base_image: full image reference from FROM (e.g. "ubuntu:22.04")
//   - base_tag: the tag portion ("22.04", or "" when absent)
//   - user: value of the last USER directive (absent when no USER)
//   - exposed_ports: []Value of port strings from EXPOSE
//   - env_names: []Value of ENV variable names (values never stored)
//   - env_secrets: []Value of {name, span} maps for ENV names that look
//     like secrets with literal values (values redacted)
//   - has_healthcheck: bool
//   - uses_add: bool (ADD used instead of COPY)
//   - run_commands: []Value of RUN command bodies (for package/sudo analysis)
//   - sudo_used: bool
//   - arg_names: []Value of ARG variable names
//   - arg_secrets: []Value of {name, span} maps for ARG names that look
//     like secrets with literal defaults (values redacted)
//   - workdir: value of the last WORKDIR directive (absent when none)
//   - labels: []Value of LABEL keys
//   - has_stopsignal: bool
//   - shell: SHELL instruction args (absent when none)
//   - uses_onbuild: bool
//   - uses_volume: bool
//   - uses_maintainer: bool (deprecated MAINTAINER instruction)
//   - copy_sources: []Value of COPY source paths (dest excluded)
//   - copy_chown_used: bool (any COPY used --chown)
//   - cmd_shell_form / entrypoint_shell_form: bool
//   - add_remote: bool (ADD fetched a remote http(s) URL)
//   - total_stages: number of build stages in the file
//   - is_final_stage: bool (this stage is the last FROM stage, i.e. the
//     image `docker build` produces by default)
//
// Safety: pure line-based parsing, no external deps. Malformed input yields
// best-effort resources plus a diagnostic, never a panic or an error.
package dockerfile

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"aegis/internal/ir"
)

// Adapter parses Dockerfiles into the canonical IR.
type Adapter struct{}

// Compile-time check that Adapter satisfies ir.Adapter.
var _ ir.Adapter = Adapter{}

// New constructs the adapter.
func New() *Adapter { return &Adapter{} }

// Name identifies the adapter.
func (Adapter) Name() string { return "dockerfile" }

// Handles reports whether this adapter parses the given path.
// Matches files named Dockerfile, Dockerfile.<suffix>, or <name>.dockerfile.
func (Adapter) Handles(path string) bool {
	base := filepath.Base(path)
	if strings.EqualFold(base, "Dockerfile") {
		return true
	}
	lower := strings.ToLower(base)
	return strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile")
}

// instruction is one parsed Dockerfile directive.
type instruction struct {
	name string // upper-cased, e.g. "FROM"
	args string // remainder of the logical line
	line int    // 1-based line where the instruction starts
}

// Parse converts Dockerfile content into one ir.Resource per build stage.
func (Adapter) Parse(path string, src []byte) ([]ir.Resource, []ir.Diagnostic, error) {
	var out []ir.Resource
	var diags []ir.Diagnostic

	// NUL bytes are never legitimate in a Dockerfile, and silently
	// keeping them suppresses findings: `USER \x00root` tokenizes to
	// user "\x00root", which no longer matches "root", so the
	// run-as-root finding vanished with no diagnostic. Strip NULs and
	// say so, so the parsed result is the file the user meant.
	if bytes.IndexByte(src, 0) >= 0 {
		diags = append(diags, ir.Diagnostic{
			Level:   "warning",
			Message: "dockerfile: file contains null bytes; stripped",
			Span:    ir.Span{File: path, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1},
		})
		cleaned := make([]byte, 0, len(src))
		for _, b := range src {
			if b != 0 {
				cleaned = append(cleaned, b)
			}
		}
		src = cleaned
	}
	ins := tokenize(string(src))

	// stage accumulates per-stage state.
	type stage struct {
		name                string
		baseImage           string
		baseTag             string
		baseSpan            ir.Span
		user                string
		userSet             bool
		userSpan            ir.Span
		ports               []ir.Value
		envNames            []ir.Value
		envSecrets          []ir.Value // []Value of map[string]ir.Value{name, span}
		argNames            []ir.Value
		argSecrets          []ir.Value // []Value of map[string]ir.Value{name, span}
		workdir             string
		workdirSet          bool
		workdirSpan         ir.Span
		labels              []ir.Value
		stopsignal          bool
		shell               string
		shellSet            bool
		shellSpan           ir.Span
		onbuild             bool
		volume              bool
		maintainer          bool
		maintainerSpan      ir.Span
		copySources         []ir.Value
		copyChown           bool
		cmdShellForm        bool
		entrypointShellForm bool
		healthcheck         bool
		usesAdd             bool
		addSpan             ir.Span
		addRemote           bool
		runs                []ir.Value
		sudo                bool
		nopasswd            bool
		span                ir.Span // stage span: FROM line to last instruction
	}

	// Global ARGs (before the first FROM) apply to every stage; attach
	// them to the first stage.
	var globalArgs []argKV

	var cur *stage
	stageCount := 0
	seedGlobalArgs := func(s *stage, line int) {
		span := ir.Span{File: path, StartLine: line, StartCol: 1, EndLine: line, EndCol: 1}
		for _, kv := range globalArgs {
			s.argNames = append(s.argNames, ir.Value{Raw: kv.name, Known: true, Span: span})
			if isSecretName(kv.name) && isLiteralValue(kv.def) && strings.TrimSpace(kv.def) != "" {
				s.argSecrets = append(s.argSecrets, secretMap(kv.name, span))
			}
		}
	}
	flush := func(endLine int) {
		if cur == nil {
			return
		}
		cur.span.EndLine = endLine
		attrs := map[string]ir.Value{
			"base_image":            {Raw: cur.baseImage, Known: true, Span: cur.baseSpan},
			"base_tag":              {Raw: cur.baseTag, Known: true, Span: cur.baseSpan},
			"exposed_ports":         {Raw: cur.ports, Known: true, Span: cur.span},
			"env_names":             {Raw: cur.envNames, Known: true, Span: cur.span},
			"env_secrets":           {Raw: cur.envSecrets, Known: true, Span: cur.span},
			"arg_names":             {Raw: cur.argNames, Known: true, Span: cur.span},
			"arg_secrets":           {Raw: cur.argSecrets, Known: true, Span: cur.span},
			"labels":                {Raw: cur.labels, Known: true, Span: cur.span},
			"has_stopsignal":        {Raw: cur.stopsignal, Known: true, Span: cur.span},
			"uses_onbuild":          {Raw: cur.onbuild, Known: true, Span: cur.span},
			"uses_volume":           {Raw: cur.volume, Known: true, Span: cur.span},
			"uses_maintainer":       {Raw: cur.maintainer, Known: true, Span: cur.span},
			"copy_sources":          {Raw: cur.copySources, Known: true, Span: cur.span},
			"copy_chown_used":       {Raw: cur.copyChown, Known: true, Span: cur.span},
			"cmd_shell_form":        {Raw: cur.cmdShellForm, Known: true, Span: cur.span},
			"entrypoint_shell_form": {Raw: cur.entrypointShellForm, Known: true, Span: cur.span},
			"has_healthcheck":       {Raw: cur.healthcheck, Known: true, Span: cur.span},
			"uses_add":              {Raw: cur.usesAdd, Known: true, Span: cur.span},
			"add_remote":            {Raw: cur.addRemote, Known: true, Span: cur.span},
			"run_commands":          {Raw: cur.runs, Known: true, Span: cur.span},
			"sudo_used":             {Raw: cur.sudo, Known: true, Span: cur.span},
			"nopasswd_sudoers":      {Raw: cur.nopasswd, Known: true, Span: cur.span},
		}
		if cur.userSet {
			attrs["user"] = ir.Value{Raw: cur.user, Known: true, Span: cur.userSpan}
		}
		if cur.workdirSet {
			attrs["workdir"] = ir.Value{Raw: cur.workdir, Known: true, Span: cur.workdirSpan}
		}
		if cur.shellSet {
			attrs["shell"] = ir.Value{Raw: cur.shell, Known: true, Span: cur.shellSpan}
		}
		if cur.usesAdd {
			attrs["add_span"] = ir.Value{Raw: true, Known: true, Span: cur.addSpan}
		}
		if cur.maintainer {
			attrs["maintainer_span"] = ir.Value{Raw: true, Known: true, Span: cur.maintainerSpan}
		}
		out = append(out, ir.Resource{
			Type:       "docker_stage",
			Name:       cur.name,
			Provider:   "docker",
			Attributes: attrs,
			Span:       cur.span,
		})
		cur = nil
	}

	for _, in := range ins {
		span := ir.Span{File: path, StartLine: in.line, StartCol: 1, EndLine: in.line, EndCol: 1}
		switch in.name {
		case "FROM":
			flush(in.line - 1)
			img, alias := parseFrom(in.args)
			name := alias
			if name == "" {
				name = "stage" + itoa(stageCount)
			}
			stageCount++
			cur = &stage{
				name:      name,
				baseImage: img,
				baseTag:   imageTag(img),
				baseSpan:  span,
				span:      ir.Span{File: path, StartLine: in.line, StartCol: 1, EndLine: in.line, EndCol: 1},
			}
			if stageCount == 1 {
				seedGlobalArgs(cur, in.line)
				globalArgs = nil
			}
		case "ARG":
			kv := parseArg(in.args)
			if kv.name == "" {
				continue
			}
			if cur == nil {
				// Global ARG before the first FROM.
				globalArgs = append(globalArgs, kv)
				continue
			}
			cur.argNames = append(cur.argNames, ir.Value{Raw: kv.name, Known: true, Span: span})
			if isSecretName(kv.name) && isLiteralValue(kv.def) && strings.TrimSpace(kv.def) != "" {
				cur.argSecrets = append(cur.argSecrets, secretMap(kv.name, span))
			}
		case "WORKDIR":
			if cur == nil {
				continue
			}
			w := strings.TrimSpace(in.args)
			// Strip surrounding quotes.
			w = strings.Trim(w, `"'`)
			if w == "" {
				continue
			}
			cur.workdir = w
			cur.workdirSet = true
			cur.workdirSpan = span
		case "LABEL":
			if cur == nil {
				continue
			}
			for _, kv := range parseLabel(in.args) {
				cur.labels = append(cur.labels, ir.Value{Raw: kv, Known: true, Span: span})
			}
		case "STOPSIGNAL":
			if cur == nil {
				continue
			}
			cur.stopsignal = true
		case "SHELL":
			if cur == nil {
				continue
			}
			cur.shell = strings.TrimSpace(in.args)
			cur.shellSet = true
			cur.shellSpan = span
		case "ONBUILD":
			if cur == nil {
				continue
			}
			cur.onbuild = true
		case "VOLUME":
			if cur == nil {
				continue
			}
			cur.volume = true
		case "MAINTAINER":
			if cur == nil {
				continue
			}
			cur.maintainer = true
			cur.maintainerSpan = span
		case "COPY":
			if cur == nil {
				continue
			}
			srcs, chown := parseCopy(in.args)
			for _, s := range srcs {
				cur.copySources = append(cur.copySources, ir.Value{Raw: s, Known: true, Span: span})
			}
			if chown {
				cur.copyChown = true
			}
		case "CMD":
			if cur == nil {
				continue
			}
			if strings.TrimSpace(in.args) != "" {
				cur.cmdShellForm = !isExecForm(in.args)
			}
		case "ENTRYPOINT":
			if cur == nil {
				continue
			}
			if strings.TrimSpace(in.args) != "" {
				cur.entrypointShellForm = !isExecForm(in.args)
			}
		case "USER":
			if cur == nil {
				continue
			}
			uf := strings.Fields(in.args)
			if len(uf) == 0 {
				continue
			}
			cur.user = uf[0]
			// strip group suffix: "user:group"
			if i := strings.Index(cur.user, ":"); i >= 0 {
				cur.user = cur.user[:i]
			}
			cur.userSet = true
			cur.userSpan = span
		case "EXPOSE":
			if cur == nil {
				continue
			}
			for _, f := range strings.Fields(in.args) {
				port := f
				if i := strings.Index(port, "/"); i >= 0 {
					port = port[:i]
				}
				cur.ports = append(cur.ports, ir.Value{Raw: port, Known: true, Span: span})
			}
		case "ENV":
			if cur == nil {
				continue
			}
			for _, kv := range parseEnv(in.args) {
				cur.envNames = append(cur.envNames, ir.Value{Raw: kv.name, Known: true, Span: span})
				if isSecretName(kv.name) && kv.literal {
					cur.envSecrets = append(cur.envSecrets, ir.Value{
						Raw: map[string]ir.Value{
							"name": {Raw: kv.name, Known: true, Span: span},
						},
						Known: true,
						Span:  span,
					})
				}
			}
		case "HEALTHCHECK":
			if cur == nil {
				continue
			}
			if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(in.args)), "NONE") {
				cur.healthcheck = true
			}
		case "ADD":
			if cur == nil {
				continue
			}
			cur.usesAdd = true
			cur.addSpan = span
			if addHasRemoteURL(in.args) {
				cur.addRemote = true
			}
		case "RUN":
			if cur == nil {
				continue
			}
			cur.runs = append(cur.runs, ir.Value{Raw: in.args, Known: true, Span: span})
			if usesSudo(in.args) {
				cur.sudo = true
			}
			if writesNopasswdSudoers(in.args) {
				cur.nopasswd = true
			}
		default:
			// Unknown instruction: Docker itself would fail the build,
			// so the line must not vanish silently (a typo'd USER or
			// HEALTHCHECK would otherwise look like an absent setting).
			diags = append(diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("dockerfile: unknown instruction %q; skipped", in.name),
				Span:    span,
			})
		}
	}
	if len(ins) > 0 {
		flush(ins[len(ins)-1].line)
	}
	// Every stage learns the total stage count (for single-stage rules).
	for i := range out {
		out[i].Attributes["total_stages"] = ir.Value{
			Raw:   stageCount,
			Known: true,
			Span:  out[i].Span,
		}
		// Only the last stage ships: `docker build` produces the final
		// stage by default. Rules about the runtime image (root user,
		// installed tools) must scope to it; intermediate build stages
		// legitimately run as root and install toolchains.
		out[i].Attributes["is_final_stage"] = ir.Value{
			Raw:   i == len(out)-1,
			Known: true,
			Span:  out[i].Span,
		}
	}
	if len(ins) == 0 && len(strings.TrimSpace(string(src))) > 0 {
		diags = append(diags, ir.Diagnostic{
			Level:   "warning",
			Message: "no Dockerfile instructions found",
			Span:    ir.Span{File: path, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1},
		})
	}
	return out, diags, nil
}

// tokenize splits source into logical lines (joining backslash
// continuations) and extracts instructions. Comments and blank lines are
// skipped. Never panics.
func tokenize(src string) []instruction {
	// Normalize newlines, then join continuations.
	src = strings.ReplaceAll(src, "\r\n", "\n")
	rawLines := strings.Split(src, "\n")
	type phys struct {
		text string
		line int
	}
	var joined []phys
	var buf strings.Builder
	start := 0
	for i, l := range rawLines {
		ln := i + 1
		trimmed := strings.TrimRight(l, " \t")
		cont := strings.HasSuffix(trimmed, "\\")
		if cont {
			if buf.Len() == 0 {
				start = ln
			}
			buf.WriteString(trimmed[:len(trimmed)-1])
			buf.WriteString(" ")
			continue
		}
		if buf.Len() > 0 {
			buf.WriteString(l)
			joined = append(joined, phys{buf.String(), start})
			buf.Reset()
		} else {
			joined = append(joined, phys{l, ln})
		}
	}
	if buf.Len() > 0 {
		joined = append(joined, phys{buf.String(), start})
	}

	var out []instruction
	for _, p := range joined {
		line := stripComment(p.text)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToUpper(fields[0])
		args := ""
		if len(line) > len(fields[0]) {
			args = strings.TrimSpace(line[len(fields[0]):])
		}
		out = append(out, instruction{name: name, args: args, line: p.line})
	}
	return out
}

// stripComment removes a # comment, respecting single/double quotes.
func stripComment(s string) string {
	var b strings.Builder
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			b.WriteRune(r)
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
			b.WriteRune(r)
		case r == '#':
			return b.String()
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// parseFrom extracts the image reference and optional AS alias from a FROM
// line. Handles flags like --platform=linux/amd64.
func parseFrom(args string) (image, alias string) {
	fields := strings.Fields(args)
	// Drop leading flags.
	i := 0
	for i < len(fields) && strings.HasPrefix(fields[i], "--") {
		// --flag=value is one field; --flag value is two.
		if !strings.Contains(fields[i], "=") {
			i++
		}
		i++
	}
	rest := fields[i:]
	if len(rest) == 0 {
		return "", ""
	}
	image = rest[0]
	for j := 1; j+1 < len(rest); j++ {
		if strings.EqualFold(rest[j], "AS") {
			alias = rest[j+1]
			break
		}
	}
	return image, alias
}

// imageTag returns the tag portion of an image reference, or "" when the
// reference carries no explicit tag (implicit :latest).
func imageTag(img string) string {
	// Strip digest.
	if i := strings.Index(img, "@"); i >= 0 {
		img = img[:i]
	}
	// Tag is the suffix after the last ':' that comes after the last '/'.
	slash := strings.LastIndex(img, "/")
	colon := strings.LastIndex(img, ":")
	if colon > slash {
		return img[colon+1:]
	}
	return ""
}

// envKV is one parsed ENV assignment.
type envKV struct {
	name    string
	literal bool // value is a static literal (not a variable expansion)
}

// parseEnv parses ENV args in both `KEY=val` and `KEY val` forms.
func parseEnv(args string) []envKV {
	var out []envKV
	fields := splitEnvFields(args)
	if len(fields) == 0 {
		return out
	}
	// If the first field contains '=', use KEY=val form for all fields.
	if strings.Contains(fields[0], "=") {
		for _, f := range fields {
			name := f
			val := ""
			if i := strings.Index(f, "="); i >= 0 {
				name = f[:i]
				val = f[i+1:]
			}
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			out = append(out, envKV{name: name, literal: isLiteralValue(val)})
		}
		return out
	}
	// KEY val [KEY val ...] form.
	for i := 0; i < len(fields); i += 2 {
		name := strings.TrimSpace(fields[i])
		if name == "" {
			continue
		}
		val := ""
		if i+1 < len(fields) {
			val = fields[i+1]
		}
		out = append(out, envKV{name: name, literal: isLiteralValue(val)})
	}
	return out
}

// splitEnvFields splits on whitespace outside quotes.
func splitEnvFields(s string) []string {
	var out []string
	var b strings.Builder
	var quote rune
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range s {
		switch {
		case quote != 0:
			b.WriteRune(r)
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
			b.WriteRune(r)
		case r == ' ' || r == '\t':
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return out
}

// isLiteralValue reports whether an ENV value is a static literal rather
// than a shell/variable expansion.
func isLiteralValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	// Strip surrounding quotes for the check.
	unq := strings.Trim(v, `"'`)
	return !strings.Contains(unq, "$")
}

// secretNameHints matches ENV names that suggest a secret.
var secretNameHints = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
	"PRIVATE_KEY", "PRIVATEKEY", "CREDENTIAL", "AUTH",
}

// isSecretName reports whether an ENV name looks like a secret.
func isSecretName(name string) bool {
	up := strings.ToUpper(name)
	for _, h := range secretNameHints {
		if strings.Contains(up, h) {
			return true
		}
	}
	return false
}

// argKV is one parsed ARG assignment: name with optional default.
type argKV struct {
	name string
	def  string
}

// parseArg parses `ARG name` or `ARG name=default`.
func parseArg(args string) argKV {
	args = strings.TrimSpace(args)
	if args == "" {
		return argKV{}
	}
	name, def := args, ""
	if i := strings.Index(args, "="); i >= 0 {
		name, def = strings.TrimSpace(args[:i]), args[i+1:]
	}
	return argKV{name: name, def: def}
}

// secretMap builds the {name, span} redacted-secret attribute value.
func secretMap(name string, span ir.Span) ir.Value {
	return ir.Value{
		Raw: map[string]ir.Value{
			"name": {Raw: name, Known: true, Span: span},
		},
		Known: true,
		Span:  span,
	}
}

// parseLabel extracts LABEL keys from KEY=val pairs. Values are discarded.
func parseLabel(args string) []string {
	var out []string
	for _, f := range splitEnvFields(args) {
		k := f
		if i := strings.Index(f, "="); i >= 0 {
			k = f[:i]
		}
		k = strings.Trim(strings.TrimSpace(k), `"'`)
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}

// isExecForm reports whether CMD/ENTRYPOINT args use the JSON-array exec
// form (["executable", "arg"]) rather than shell form.
func isExecForm(args string) bool {
	return strings.HasPrefix(strings.TrimSpace(args), "[")
}

// parseCopy extracts COPY source paths (destination excluded) and reports
// whether --chown was passed. Handles flag=value and flag value forms,
// plus the JSON-array form COPY ["src", "dst"].
func parseCopy(args string) (srcs []string, chown bool) {
	trimmed := strings.TrimSpace(args)
	if strings.HasPrefix(trimmed, "[") {
		// JSON-array form: quoted strings; all but the last are sources.
		var strs []string
		var b strings.Builder
		var quote rune
		flush := func() {
			if b.Len() > 0 {
				strs = append(strs, b.String())
				b.Reset()
			}
		}
		for _, r := range trimmed {
			switch {
			case quote != 0:
				if r == quote {
					quote = 0
				} else {
					b.WriteRune(r)
				}
			case r == '"' || r == '\'':
				quote = r
			case r == ',' || r == '[' || r == ']':
				flush()
			}
		}
		flush()
		if len(strs) > 1 {
			srcs = strs[:len(strs)-1]
		}
		return srcs, false
	}
	fields := strings.Fields(args)
	var rest []string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if !strings.HasPrefix(f, "--") {
			rest = append(rest, f)
			continue
		}
		name := f
		if eq := strings.Index(f, "="); eq >= 0 {
			name = f[:eq]
		} else if i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "--") {
			// --flag value form: consume the value.
			i++
		}
		if name == "--chown" {
			chown = true
		}
	}
	// All but the last non-flag field are sources; the last is the dest.
	if len(rest) > 1 {
		srcs = rest[:len(rest)-1]
	}
	return srcs, chown
}

// addHasRemoteURL reports whether an ADD instruction fetches an http(s)
// URL (any source field but the destination).
func addHasRemoteURL(args string) bool {
	fields := strings.Fields(args)
	var rest []string
	for _, f := range fields {
		if !strings.HasPrefix(f, "--") {
			rest = append(rest, f)
		}
	}
	if len(rest) < 2 {
		return false
	}
	for _, s := range rest[:len(rest)-1] {
		l := strings.ToLower(s)
		if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			return true
		}
	}
	return false
}

// usesSudo reports whether a RUN command invokes sudo.
func usesSudo(cmd string) bool {
	for _, tok := range strings.Fields(cmd) {
		// strip shell operators
		t := strings.Trim(tok, ";&|()")
		if t == "sudo" {
			return true
		}
	}
	return false
}

// writesNopasswdSudoers reports whether a RUN command configures
// passwordless sudo, i.e. it writes a NOPASSWD entry to a sudoers file
// (/etc/sudoers or /etc/sudoers.d/...). Both tokens are required: a
// bare NOPASSWD mention (e.g. in a comment or a note file) configures
// nothing, and merely reading /etc/sudoers does not grant anything.
func writesNopasswdSudoers(cmd string) bool {
	return strings.Contains(cmd, "NOPASSWD") && strings.Contains(cmd, "sudoers")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [16]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
