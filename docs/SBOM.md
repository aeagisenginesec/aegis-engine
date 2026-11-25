# SBOM generation for scanned projects

`aegis scan --sbom spdx-json|cyclonedx-json <dir>` writes a dependency
inventory for the scanned project **alongside** the normal findings
report. The findings report is unchanged; the SBOM is a second output
file. This is the v2.4.0 implementation of the item deferred in the
v2.3.0 blueprint (Compliance #9).

> **Not to be confused with `SBOM.md` at the repo root.** That file is
> Aegis's *own* Go-module dependency SBOM. `--sbom` describes the
> *scanned project*, not Aegis itself.

## Usage

```bash
aegis scan ./my-infra --sbom spdx-json
# writes sbom.spdx.json in the working directory

aegis scan ./my-infra --sbom cyclonedx-json --sbom-out ./out/bom.json
# writes the CycloneDX document to the given path
```

- `--sbom spdx-json` — SPDX 2.3 JSON (primary format: the widest-consumed
  SBOM shape; `spdxVersion: SPDX-2.3`, `dataLicense: CC0-1.0`).
- `--sbom cyclonedx-json` — CycloneDX 1.6 JSON (`bomFormat: CycloneDX`,
  `specVersion: 1.6`).
- Default output: `sbom.spdx.json` / `sbom.cyclonedx.json` in the working
  directory. A note naming the file and package count goes to stderr.
- The scan's exit code is unchanged: findings still drive 0/1/2. A failure
  to write the SBOM is exit 2.
- Default SBOM filenames are skipped by discovery on later scans, so a
  previous SBOM sitting in the scanned tree is not re-parsed as a
  manifest. A custom `--sbom-out` path inside the scanned tree is not
  skipped — keep SBOM outputs out of the tree or name them accordingly.

## What is inventoried

Only what the discovery layer already parses — nothing is fetched,
executed, or resolved over the network:

| Source | Inventory entry |
|---|---|
| `terraform { required_providers { ... } }` | Terraform provider: name = source address (`hashicorp/aws`), version = constraint string (`~> 5.0`) |
| `module "name" { source = "..." }` | Terraform module: name = call name, source as written, version = static `version` input or git `?ref=` where pinned |
| Dockerfile `FROM` lines | Container image: name without tag/digest, version = tag |
| Compose service `image:` | Container image, same shape as Dockerfile |

Every entry records the file and line of its declaration. Entries are
deduplicated and sorted deterministically; a project with no
dependencies yields a valid, empty document (zero packages/components),
not an error.

## Deliberate boundaries

- **No transitive resolution.** A provider's own dependencies, a
  module's nested modules, and an image's layers/packages are not
  enumerated — only the direct references written in the scanned files.
- **No lock files.** Provider versions are reported as the constraint
  string, not the exact locked version (`.terraform.lock.hcl` is skipped
  by discovery). A constraint is not a version; consumers must not treat
  `~> 5.0` as the resolved version.
- **No registry lookups.** Unpinned versions (unpinned modules, untagged
  images, providers without a constraint) are reported with an empty
  version — never resolved to "latest". An untagged image means implicit
  `:latest`; the SBOM says "unknown", not "latest".
- **No K8s / Pulumi / CloudFormation / ARM / Bicep dependencies yet.**
  Those adapters do not currently surface a dependency-shaped attribute
  (e.g. k8s container images, Pulumi provider packages), so there is
  nothing to collect without new parsing. Adding a source means adding
  one case to `internal/sbom.Collect`, not a redesign.
- **No relationships beyond DESCRIBES / dependsOn.** The documents state
  that the scanned project describes/depends on each package. No
  CONTAINS or DEPENDS_ON edges between packages are invented: Aegis does
  not know the containment graph, and an SBOM must not assert one.
- **No purl is invented for Terraform.** The purl spec has no terraform
  type, so Terraform entries are located by registry URL
  (`downloadLocation` / external reference), not a made-up purl.
  Container images carry a real `pkg:oci/...` purl.

## Document fields

Both formats stamp the tool identifier as `aegis-<version>` (the
`internal/version` constant — 2.3.0 until the v2.4.0 release bump) and
the creation timestamp in UTC. SPDX document namespaces and CycloneDX
serial numbers are derived from the target path and timestamp, so two
runs never claim the same document identity. Apart from the timestamp,
output is deterministic (sorted packages, stable IDs).
