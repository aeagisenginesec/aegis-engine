package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"aegis/internal/ir"
	"aegis/internal/version"
)

// CycloneDX 1.6 JSON document shape (subset: the fields the spec requires
// for a minimal valid BOM plus component external references). The root
// component is the scanned project itself; every collected dependency is
// a component it depends on.

type cycloneDXDocument struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	SerialNumber string               `json:"serialNumber"`
	Version      int                  `json:"version"`
	Metadata     cycloneDXMetadata    `json:"metadata"`
	Components   []cycloneDXComponent `json:"components"`
	Dependencies []cycloneDXDep       `json:"dependencies"`
}

type cycloneDXMetadata struct {
	Timestamp string             `json:"timestamp"`
	Tools     []cycloneDXTool    `json:"tools"`
	Component cycloneDXComponent `json:"component"`
}

type cycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cycloneDXComponent struct {
	Type               string                 `json:"type"`
	BOMRef             string                 `json:"bom-ref"`
	Name               string                 `json:"name"`
	Version            string                 `json:"version,omitempty"`
	PURL               string                 `json:"purl,omitempty"`
	ExternalReferences []cycloneDXExternalRef `json:"externalReferences,omitempty"`
}

type cycloneDXExternalRef struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

type cycloneDXDep struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// WriteCycloneDX renders deps as a CycloneDX 1.6 JSON document for the
// scanned target. An empty dependency list still yields a valid document
// with zero components and a root dependency entry with no dependsOn.
// The serial number is a deterministic UUID-shaped hash of the target and
// timestamp (a version-5-style UUID is not required; uniqueness per
// document is what the spec asks for).
func WriteCycloneDX(w io.Writer, target string, deps []ir.Dependency, now time.Time) error {
	if deps == nil {
		deps = []ir.Dependency{}
	}
	ts := now.UTC().Format(time.RFC3339)
	rootRef := "aegis:project:" + docName(target)
	doc := cycloneDXDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + uuidFrom(target, ts),
		Version:      1,
		Metadata: cycloneDXMetadata{
			Timestamp: ts,
			Tools: []cycloneDXTool{{
				Vendor:  "Aegis",
				Name:    "aegis",
				Version: version.Version,
			}},
			Component: cycloneDXComponent{
				Type:   "application",
				BOMRef: rootRef,
				Name:   docName(target),
			},
		},
		Components:   []cycloneDXComponent{},
		Dependencies: []cycloneDXDep{{Ref: rootRef}},
	}
	var refs []string
	for i, d := range deps {
		ref := componentRef(d, i)
		refs = append(refs, ref)
		doc.Components = append(doc.Components, cycloneDXComponent{
			Type:               componentType(d),
			BOMRef:             ref,
			Name:               d.Name,
			Version:            d.Version,
			PURL:               componentPURL(d),
			ExternalReferences: componentExternalRefs(d),
		})
	}
	if len(refs) > 0 {
		doc.Dependencies[0].DependsOn = refs
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// componentType maps a dependency kind to a CycloneDX component type.
func componentType(d ir.Dependency) string {
	if d.Kind == KindContainerImage {
		return "container"
	}
	return "library"
}

// componentRef is the bom-ref for a component: its purl when one exists,
// else a stable Aegis-scoped identifier. The purl doubles as the
// dependency-graph edge target, so graph consumers can resolve it.
func componentRef(d ir.Dependency, i int) string {
	if p := componentPURL(d); p != "" {
		return p
	}
	return fmt.Sprintf("aegis:dep:%d", i+1)
}

// componentPURL returns the package-URL locator for container images
// only; Terraform has no purl type in the spec, so those components get
// no purl (their registry page is an external reference instead).
func componentPURL(d ir.Dependency) string {
	if d.Kind == KindContainerImage {
		return ociPurl(d)
	}
	return ""
}

// componentExternalRefs returns the registry page for Terraform registry
// entries (providers and modules) and the repository URL for git module
// sources; container images carry their purl instead and get none.
func componentExternalRefs(d ir.Dependency) []cycloneDXExternalRef {
	var url string
	switch d.Kind {
	case KindTerraformProvider:
		if d.Source != "" {
			url = "https://registry.terraform.io/providers/" + d.Source
		}
	case KindTerraformModule:
		if isRegistryModule(d.Source) {
			url = "https://registry.terraform.io/modules/" + d.Source
		} else if u := gitURL(d.Source); u != "" {
			url = u
		}
	}
	if url == "" {
		return nil
	}
	return []cycloneDXExternalRef{{URL: url, Type: "website"}}
}

// uuidFrom formats a SHA-256 hash as a UUID (8-4-4-4-12), so the
// serialNumber is a well-formed urn:uuid without importing a UUID
// library for one call site.
func uuidFrom(target, ts string) string {
	sum := sha256.Sum256([]byte(target + "\x00" + ts))
	hex := fmt.Sprintf("%x", sum)
	return strings.Join([]string{
		hex[0:8], hex[8:12], hex[12:16], hex[16:20], hex[20:32],
	}, "-")
}
