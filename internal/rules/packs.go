package rules

import (
	"strings"

	"aegis/internal/rules/alibaba"
	"aegis/internal/rules/aws"
	"aegis/internal/rules/azure"
	"aegis/internal/rules/compose"
	"aegis/internal/rules/docker"
	"aegis/internal/rules/gcp"
	"aegis/internal/rules/k8s"
	"aegis/internal/rules/oci"
	"aegis/internal/rules/supplychain"
	"aegis/internal/rules/terraform"
)

// KnownPacks lists the rule packs selectable via --rules, in stable order.
var KnownPacks = []string{"alibaba", "aws", "azure", "compose", "docker", "gcp", "k8s", "oci", "supplychain", "terraform"}

// RegistryFor builds a registry with the named packs. An empty list or the
// name "all" selects every known pack. Unknown names are ignored; use
// UnknownPacks to report them.
func RegistryFor(packs ...string) *Registry {
	reg := NewRegistry()
	names := normalizePacks(packs)
	for _, n := range names {
		switch n {
		case "alibaba":
			for _, r := range alibaba.Rules() {
				reg.Register(r)
			}
		case "aws":
			for _, r := range aws.Rules() {
				reg.Register(r)
			}
		case "azure":
			for _, r := range azure.Rules() {
				reg.Register(r)
			}
		case "compose":
			for _, r := range compose.Rules() {
				reg.Register(r)
			}
		case "docker":
			for _, r := range docker.Rules() {
				reg.Register(r)
			}
		case "gcp":
			for _, r := range gcp.Rules() {
				reg.Register(r)
			}
		case "k8s":
			for _, r := range k8s.Rules() {
				reg.Register(r)
			}
		case "oci":
			for _, r := range oci.Rules() {
				reg.Register(r)
			}
		case "supplychain":
			for _, r := range supplychain.Rules() {
				reg.Register(r)
			}
		case "terraform":
			for _, r := range terraform.Rules() {
				reg.Register(r)
			}
		}
	}
	return reg
}

// UnknownPacks returns the subset of packs that are not known.
func UnknownPacks(packs []string) []string {
	known := map[string]bool{}
	for _, k := range KnownPacks {
		known[k] = true
	}
	var out []string
	for _, p := range packs {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || p == "all" {
			continue
		}
		if !known[p] {
			out = append(out, p)
		}
	}
	return out
}

// normalizePacks expands "all"/empty to every pack, dedupes, keeps order.
func normalizePacks(packs []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, p := range packs {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || p == "all" {
			for _, k := range KnownPacks {
				add(k)
			}
			continue
		}
		add(p)
	}
	if len(out) == 0 {
		for _, k := range KnownPacks {
			add(k)
		}
	}
	return out
}
