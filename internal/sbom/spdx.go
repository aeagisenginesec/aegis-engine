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

// SPDX 2.3 JSON document shape (subset: the fields the spec requires for
// a minimal valid document plus package external references). Only
// standards-shaped fields are emitted; nothing Aegis-specific leaks into
// the package list beyond the tool identifier in creationInfo.

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	Supplier         string            `json:"supplier"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

// WriteSPDX renders deps as an SPDX 2.3 JSON document for the scanned
// target. An empty dependency list still yields a valid document with
// zero packages and zero DESCRIBES relationships. The document name is
// "<target>-sbom"; the namespace is a stable URI derived from the target
// and timestamp so two runs never claim the same document identity.
func WriteSPDX(w io.Writer, target string, deps []ir.Dependency, now time.Time) error {
	if deps == nil {
		deps = []ir.Dependency{}
	}
	ts := now.UTC().Format(time.RFC3339)
	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              docName(target) + "-sbom",
		DocumentNamespace: spdxNamespace(target, ts),
		CreationInfo: spdxCreationInfo{
			Created:  ts,
			Creators: []string{"Tool: aegis-" + version.Version},
		},
		Packages:      []spdxPackage{},
		Relationships: []spdxRelationship{},
	}
	for i, d := range deps {
		id := fmt.Sprintf("SPDXRef-Package-%d", i+1)
		doc.Packages = append(doc.Packages, spdxPackage{
			SPDXID:           id,
			Name:             d.Name,
			VersionInfo:      d.Version,
			DownloadLocation: downloadLocation(d),
			FilesAnalyzed:    false,
			Supplier:         "NOASSERTION",
			ExternalRefs:     externalRefs(d),
		})
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelatedSPDXElement: id,
			RelationshipType:   "DESCRIBES",
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// spdxNamespace builds a unique document namespace URI. The hash binds
// it to this target and creation time; it is an identifier, not a
// fetchable URL.
func spdxNamespace(target, ts string) string {
	sum := sha256.Sum256([]byte(target + "\x00" + ts))
	return fmt.Sprintf("https://github.com/aegis/engine/sbom/%x", sum)
}

// downloadLocation returns the best fetchable location for a dependency,
// or NOASSERTION when none is known statically. Registry addresses map
// to their registry pages; git sources map to the repository URL (the
// ?ref= and //subdir suffixes stripped); container images have no
// canonical download page from the reference alone.
func downloadLocation(d ir.Dependency) string {
	switch d.Kind {
	case KindTerraformProvider:
		if d.Source != "" {
			return "https://registry.terraform.io/providers/" + d.Source
		}
	case KindTerraformModule:
		if isRegistryModule(d.Source) {
			return "https://registry.terraform.io/modules/" + d.Source
		}
		if u := gitURL(d.Source); u != "" {
			return u
		}
	}
	return "NOASSERTION"
}

// externalRefs returns the package-URL locator for container images
// (pkg:oci) and the registry page for Terraform registry entries; nil
// when no stable locator exists. No purl type is invented for Terraform:
// the purl spec has no terraform type, so registry entries are located
// by URL instead of a made-up purl.
func externalRefs(d ir.Dependency) []spdxExternalRef {
	switch d.Kind {
	case KindContainerImage:
		if p := ociPurl(d); p != "" {
			return []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  p,
			}}
		}
	case KindTerraformProvider:
		if d.Source != "" {
			return []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "url",
				ReferenceLocator:  "https://registry.terraform.io/providers/" + d.Source,
			}}
		}
	case KindTerraformModule:
		if isRegistryModule(d.Source) {
			return []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "url",
				ReferenceLocator:  "https://registry.terraform.io/modules/" + d.Source,
			}}
		}
	}
	return nil
}

// ociPurl builds a pkg:oci locator for a container image: name@tag when
// tagged, name@digest when pinned by digest, bare name otherwise (a
// version-less purl is still a valid locator for the image stream).
func ociPurl(d ir.Dependency) string {
	if d.Name == "" {
		return ""
	}
	p := "pkg:oci/" + d.Name
	if d.Version != "" {
		return p + "@" + d.Version
	}
	if i := strings.Index(d.Source, "@"); i >= 0 {
		return p + "@" + d.Source[i+1:]
	}
	return p
}

// isRegistryModule reports whether a module source is a Terraform
// Registry address (namespace/name/provider, no scheme, no slashes
// beyond the two separators, no .git suffix).
func isRegistryModule(source string) bool {
	if source == "" || strings.Contains(source, "://") || strings.HasSuffix(source, ".git") {
		return false
	}
	parts := strings.Split(source, "/")
	return len(parts) == 3
}

// gitURL extracts the repository URL from a git module source
// ("git::https://example.com/repo.git//subdir?ref=v1" → the https URL
// without the git:: prefix, subdir, or query), or "" when the source is
// not a git URL.
func gitURL(source string) string {
	s := source
	s = strings.TrimPrefix(s, "git::")
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "ssh://") {
		return ""
	}
	if i := strings.Index(s, "?"); i >= 0 {
		s = s[:i]
	}
	// A "//" after the scheme ("://") starts the subdirectory.
	if scheme := strings.Index(s, "://"); scheme >= 0 {
		if j := strings.Index(s[scheme+3:], "//"); j >= 0 {
			s = s[:scheme+3+j]
		}
	}
	return s
}
