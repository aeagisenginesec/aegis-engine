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
//
// Safety: pure line-based parsing, no external deps. Malformed input yields
// best-effort resources plus a diagnostic, never a panic or an error.
package dockerfile

import (
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
	ins := tokenize(string(src))
	var out []ir.Resource
	var diags []ir.Diagnostic

	// stage accumulates per-stage state.
	type stage struct {
		name        string
		baseImage   string
		baseTag     string
		baseSpan    ir.Span
		user        string
		userSet     bool
		userSpan    ir.Span
		ports       []ir.Value
		envNames    []ir.Value
		envSecrets  []ir.Value // []Value of map[string]ir.Value{name, span}
		healthcheck bool
		usesAdd     bool
		addSpan     ir.Span
		runs        []ir.Value
		sudo        bool
		span        ir.Span // stage span: FROM line to last instruction
	}

	var cur *stage
	stageCount := 0
	flush := func(endLine int) {
		if cur == nil {
			return
		}
		cur.span.EndLine = endLine
		attrs := map[string]ir.Value{
			"base_image":      {Raw: cur.baseImage, Known: true, Span: cur.baseSpan},
			"base_tag":        {Raw: cur.baseTag, Known: true, Span: cur.baseSpan},
			"exposed_ports":   {Raw: cur.ports, Known: true, Span: cur.span},
			"env_names":       {Raw: cur.envNames, Known: true, Span: cur.span},
			"env_secrets":     {Raw: cur.envSecrets, Known: true, Span: cur.span},
			"has_healthcheck": {Raw: cur.healthcheck, Known: true, Span: cur.span},
			"uses_add":        {Raw: cur.usesAdd, Known: true, Span: cur.span},
			"run_commands":    {Raw: cur.runs, Known: true, Span: cur.span},
			"sudo_used":       {Raw: cur.sudo, Known: true, Span: cur.span},
		}
		if cur.userSet {
			attrs["user"] = ir.Value{Raw: cur.user, Known: true, Span: cur.userSpan}
		}
		if cur.usesAdd {
			attrs["add_span"] = ir.Value{Raw: true, Known: true, Span: cur.addSpan}
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
		case "RUN":
			if cur == nil {
				continue
			}
			cur.runs = append(cur.runs, ir.Value{Raw: in.args, Known: true, Span: span})
			if usesSudo(in.args) {
				cur.sudo = true
			}
		}
	}
	if len(ins) > 0 {
		flush(ins[len(ins)-1].line)
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
	if strings.Contains(unq, "$") {
		return false
	}
	return true
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
