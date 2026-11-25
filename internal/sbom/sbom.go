// Package sbom builds a dependency inventory (SBOM) for the project a
// scan just parsed, and renders it as SPDX 2.3 JSON or CycloneDX 1.6 JSON.
//
// Sources (only what the discovery layer already parses — nothing is
// fetched, executed, or resolved over the network):
//
//   - Terraform required_providers entries (name, source, version constraint)
//   - Terraform module calls (source, plus a version input or git ?ref=
//     where one is pinned statically)
//   - Dockerfile base images (FROM lines, via docker_stage resources)
//   - Compose service images (via compose_service resources)
//
// Deliberate boundaries (v2.4.0, smallest coherent version):
//
//   - NO transitive dependency resolution. A provider's own dependencies,
//     a module's nested modules, and an image's layers/packages are not
//     enumerated — only the direct references written in the scanned files.
//   - NO lock files. Terraform provider versions are reported as the
//     constraint string ("~> 5.0"), not the exact locked version; the
//     .terraform.lock.hcl file is skipped by discovery.
//   - NO registry lookups. Versions that are not pinned in the source
//     (unpinned modules, untagged images, providers without a constraint)
//     are reported with an empty version, not resolved to "latest".
//   - NO Kubernetes / Pulumi / CloudFormation / ARM / Bicep dependencies
//     yet: those adapters do not currently surface a dependency-shaped
//     attribute (k8s container images, Pulumi provider packages), so
//     there is nothing to collect without new parsing. Adding a source
//     means adding one case to Collect, not a redesign.
package sbom

import (
	"path/filepath"
	"sort"
	"strings"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
)

// Kinds of dependencies Collect recognizes.
const (
	KindTerraformProvider = "terraform-provider"
	KindTerraformModule   = "terraform-module"
	KindContainerImage    = "container-image"
)

// Collect builds the dependency inventory from the modules and resources
// a scan produced. It never panics on unexpected shapes: an unparseable
// attribute, a non-string value, or a nil input is skipped, never fatal.
// The result is deduplicated on (kind, name, version, source) and sorted
// deterministically by (kind, name, version, source, file).
func Collect(mods []terraform.Module, resources []ir.Resource) []ir.Dependency {
	out := []ir.Dependency{}
	for _, mod := range mods {
		for _, req := range mod.ProviderReqs {
			out = append(out, providerDependency(req))
		}
		for _, mc := range mod.ModuleCalls {
			if d, ok := moduleDependency(mc); ok {
				out = append(out, d)
			}
		}
	}
	for _, r := range resources {
		switch r.Type {
		case "docker_stage":
			if d, ok := imageDependency(r, "base_image"); ok {
				out = append(out, d)
			}
		case "compose_service":
			if d, ok := imageDependency(r, "image"); ok {
				out = append(out, d)
			}
		}
	}
	return dedupSort(out)
}

// providerDependency converts one required_providers entry. The package
// name is the source address when known ("hashicorp/aws"), else the local
// name; the version is the constraint string as written.
func providerDependency(req terraform.ProviderReq) ir.Dependency {
	name := req.Source
	if name == "" {
		name = req.Name
	}
	return ir.Dependency{
		Kind:    KindTerraformProvider,
		Name:    name,
		Version: req.Version,
		Source:  req.Source,
		File:    req.Span.File,
		Line:    req.Span.StartLine,
	}
}

// moduleDependency converts one module call. A call with no static source
// (e.g. source = var.module_source) contributes nothing — an unknown
// source is not a dependency. The version comes from a static `version`
// input when present, else from a git ?ref= query parameter.
func moduleDependency(mc terraform.ModuleCall) (ir.Dependency, bool) {
	if strings.TrimSpace(mc.Source) == "" {
		return ir.Dependency{}, false
	}
	version := ""
	if v, ok := mc.Inputs["version"]; ok {
		if s, ok := v.AsString(); ok {
			version = s
		}
	}
	if version == "" {
		version = gitRef(mc.Source)
	}
	return ir.Dependency{
		Kind:    KindTerraformModule,
		Name:    mc.Name,
		Version: version,
		Source:  mc.Source,
		File:    mc.Span.File,
		Line:    mc.Span.StartLine,
	}, true
}

// gitRef extracts the ?ref= value from a git module source
// ("git::https://example.com/repo.git?ref=v1.2.3"), or "" when absent.
func gitRef(source string) string {
	i := strings.Index(source, "?ref=")
	if i < 0 {
		return ""
	}
	ref := source[i+len("?ref="):]
	if j := strings.Index(ref, "&"); j >= 0 {
		ref = ref[:j]
	}
	return ref
}

// imageDependency converts a container image reference held in the named
// attribute of a docker_stage or compose_service resource. The name is
// the reference without tag or digest; the version is the tag ("" when
// untagged, i.e. implicit :latest — reported as unknown, not as
// "latest"); a digest reference keeps the digest in Source so two
// digests of the same image stay distinct entries.
func imageDependency(r ir.Resource, attr string) (ir.Dependency, bool) {
	v, ok := r.Attributes[attr]
	if !ok {
		return ir.Dependency{}, false
	}
	ref, ok := v.AsString()
	if !ok || strings.TrimSpace(ref) == "" {
		return ir.Dependency{}, false
	}
	name, tag := splitImageRef(ref)
	return ir.Dependency{
		Kind:    KindContainerImage,
		Name:    name,
		Version: tag,
		Source:  ref,
		File:    v.Span.File,
		Line:    v.Span.StartLine,
	}, true
}

// splitImageRef splits "registry/repo/name:tag@digest" into the bare name
// and the tag ("" when there is no tag). A digest alone yields no tag:
// the digest is identity, not a version.
func splitImageRef(ref string) (name, tag string) {
	// Strip the digest first, then split the tag from what remains:
	// "my-app:1.0@sha256:..." is image my-app, tag 1.0, pinned by digest.
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	// A tag is the suffix after the last ':' that comes after the last
	// '/' (a ':' before the last '/' is a registry port, e.g.
	// localhost:5000/img).
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, ""
}

// docName returns the human-readable project name for SBOM documents:
// the base of the target path, so "." scans are named after their
// directory and absolute paths after their leaf directory.
func docName(target string) string {
	if target == "" {
		return "project"
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		abs = target
	}
	if base := filepath.Base(abs); base != "" && base != "." && base != "/" {
		return base
	}
	return target
}

// first occurrence keeps its file/line — and sorts deterministically.
func dedupSort(deps []ir.Dependency) []ir.Dependency {
	seen := map[string]bool{}
	out := deps[:0]
	for _, d := range deps {
		key := strings.Join([]string{d.Kind, d.Name, d.Version, d.Source}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.File < b.File
	})
	return out
}
