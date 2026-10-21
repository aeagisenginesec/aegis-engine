package aws

import (
	"regexp"
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-856: EC2 instance on an end-of-life OS image
//
// GCP already has this check (AEGIS-GCP-294, High) for google_compute_instance
// boot-disk images; AWS had no equivalent, so an EC2 instance pinned to a
// Debian 10 (Buster, EOL June 2022) AMI produced no finding at all.
//
// Severity: High, mirroring GCP-294. An EOL OS receives no security
// patches; the exposure is real whether or not the instance is public,
// and the fix (migrate to a supported image) is the same.
//
// Coverage:
//   - aws_instance / aws_launch_template / aws_launch_configuration /
//     aws_spot_instance_request: the ami / image_id attribute, when it
//     carries a recognizable OS marker (AMI name fragment, e.g.
//     "debian-10-amd64-20230101", "ubuntu-18.04-amd64-server").
//   - data "aws_ami" (IR type terraform_data, name "aws_ami.<name>"):
//     name-filter values (globs stripped) and name_regex, when they
//     select an EOL image (e.g. values = ["debian-10-amd64-*"]).
//
// Deliberate silence:
//   - Opaque AMI IDs (ami-0abc123...) carry no OS signal: unknown != EOL,
//     stay quiet.
//   - Unresolved / interpolated values: stay quiet (cannot determine).
//   - Supported images (Debian 12, Ubuntu 22.04/24.04, AL2023, RHEL 8/9,
//     Windows Server 2019/2022): stay quiet.
// ---------------------------------------------------------------------------

type ec2EOLImage struct{}

func (ec2EOLImage) ID() string { return "AEGIS-AWS-856" }
func (ec2EOLImage) Title() string {
	return "EC2 instance on end-of-life OS image"
}
func (ec2EOLImage) Description() string {
	return "An EC2 instance (or launch template/configuration, or AMI " +
		"lookup) pinned to an end-of-life OS image (e.g. Debian 10, " +
		"Ubuntu 18.04, CentOS 7, Amazon Linux 1, Windows Server 2012) " +
		"no longer receives security patches. Migrate to a supported image."
}
func (ec2EOLImage) Severity() ir.Severity { return ir.SeverityHigh }

func (ec2EOLImage) AppliesTo(resType string) bool {
	switch resType {
	case "aws_instance",
		"aws_launch_template",
		"aws_launch_configuration",
		"aws_spot_instance_request",
		"terraform_data":
		return true
	}
	return false
}

// eolOSPatterns matches recognizable end-of-life OS markers in an image
// reference (AMI name fragment, filter glob, image ID string). Each
// pattern is anchored with \b so "debian-101" or "0debian12" never match:
// the version token must be a whole token. The input is lowercased and
// glob "*" characters are stripped before matching. Codenames (buster,
// stretch, xenial, ...) are matched as whole words.
var eolOSPatterns = []struct {
	re   *regexp.Regexp
	name string
}{
	// Debian 9 (Stretch, EOL June 2022) and 10 (Buster, EOL June 2022).
	{regexp.MustCompile(`\bdebian[-_. ]?(9|10)\b`), "Debian 9/10"},
	{regexp.MustCompile(`\b(stretch|buster)\b`), "Debian 9/10"},
	// Ubuntu LTS/interim releases past EOL: 16.04 (2021), 18.04 (2023),
	// 20.04 (2025), 21.04/21.10/22.10/23.04/23.10 (interim, all EOL).
	// 22.04 (2027) and 24.04 (2029) are supported: deliberately absent.
	{regexp.MustCompile(`\bubuntu[-_. ]?(1604|16\.04|1804|18\.04|2004|20\.04|2104|21\.04|2110|21\.10|2210|22\.10|2304|23\.04|2310|23\.10)\b`), "Ubuntu (EOL release)"},
	{regexp.MustCompile(`\b(xenial|bionic|focal|hirsute|impish|kinetic|lunar|mantic)\b`), "Ubuntu (EOL release)"},
	// CentOS 6/7/8 (all EOL; CentOS Stream 8 EOL May 2024).
	{regexp.MustCompile(`\bcentos[-_. ]?(stream[-_. ]?)?(6|7|8)\b`), "CentOS 6/7/8"},
	// Amazon Linux 1 (EOL Dec 2023) and Amazon Linux 2 (EOL Jun 2026).
	// AL2023 is supported: deliberately absent.
	{regexp.MustCompile(`\bamzn[-_. ]?(ami[-_. ]?)?(1|2018)\b`), "Amazon Linux 1"},
	{regexp.MustCompile(`\bamzn2\b`), "Amazon Linux 2"},
	{regexp.MustCompile(`\bamazon[-_. ]?linux[-_. ]?(1|2018)\b`), "Amazon Linux 1"},
	{regexp.MustCompile(`\bamazon[-_. ]?linux[-_. ]?2\b`), "Amazon Linux 2"},
	// RHEL 7 (EOL June 2024). RHEL 8/9 supported: absent.
	{regexp.MustCompile(`\brhel[-_. ]?7\b`), "RHEL 7"},
	{regexp.MustCompile(`\bred[-_. ]?hat[-_. ]?enterprise[-_. ]?linux[-_. ]?7\b`), "RHEL 7"},
	// Windows Server 2012 / 2012 R2 (EOL Oct 2023). 2016+ supported
	// (2016 EOL Jan 2027): absent.
	{regexp.MustCompile(`\bwindows[-_. ]?(server[-_. ]?)?2012([-_. ]?r2)?\b`), "Windows Server 2012"},
}

// eolOSMatch reports whether s carries a recognizable EOL OS marker and
// which one. Returns ("", false) when the version cannot be determined.
func eolOSMatch(s string) (string, bool) {
	norm := strings.ToLower(strings.ReplaceAll(s, "*", ""))
	for _, p := range eolOSPatterns {
		if p.re.MatchString(norm) {
			return p.name, true
		}
	}
	return "", false
}

func (ec2EOLImage) Check(r ir.Resource) []ir.Finding {
	if r.Type == "terraform_data" {
		return eolAMISelection(r)
	}
	for _, attr := range []string{"ami", "image_id"} {
		v, ok := r.Attributes[attr]
		if !ok || !v.Known {
			continue
		}
		s, ok := v.AsString()
		if !ok || strings.TrimSpace(s) == "" {
			continue
		}
		if name, found := eolOSMatch(s); found {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-856",
				Title:       (ec2EOLImage{}).Title(),
				Description: (ec2EOLImage{}).Description(),
				Severity:    ir.SeverityHigh,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: attr,
					Span:      evidenceSpan(v.Span, r.Span),
					Actual:    "image pinned to " + name + " (end of life)",
					Expected:  "supported image (e.g. Debian 12, Ubuntu 22.04/24.04, AL2023)",
				},
			}}
		}
	}
	return nil
}

// eolAMISelection fires when a data "aws_ami" lookup selects an EOL image
// via its name filter values or name_regex. The data source is the defect:
// every instance launched from the lookup inherits the EOL image.
func eolAMISelection(r ir.Resource) []ir.Finding {
	if !strings.HasPrefix(r.Name, "aws_ami.") {
		return nil
	}
	// filter blocks: only the "name" filter selects by image name.
	for _, fb := range blockList(r.Attributes, "filter") {
		nameVal, ok := fb["name"]
		if !ok || !nameVal.Known {
			continue
		}
		name, ok := nameVal.AsString()
		if !ok || strings.ToLower(strings.TrimSpace(name)) != "name" {
			continue
		}
		valsVal, ok := fb["values"]
		if !ok || !valsVal.Known {
			continue
		}
		vals, ok := valsVal.AsList()
		if !ok {
			continue
		}
		for _, item := range vals {
			s, ok := item.AsString()
			if !ok {
				continue
			}
			if osName, found := eolOSMatch(s); found {
				return []ir.Finding{{
					RuleID:      "AEGIS-AWS-856",
					Title:       (ec2EOLImage{}).Title(),
					Description: (ec2EOLImage{}).Description(),
					Severity:    ir.SeverityHigh,
					Resource:    r.Address(),
					Evidence: ir.Evidence{
						Attribute: "filter.values",
						Span:      evidenceSpan(item.Span, r.Span),
						Actual:    "AMI lookup selects " + osName + " (end of life)",
						Expected:  "AMI lookup selecting a supported image",
					},
				}}
			}
		}
	}
	// name_regex selects by image-name pattern.
	if v, ok := r.Attributes["name_regex"]; ok && v.Known {
		if s, ok := v.AsString(); ok {
			if osName, found := eolOSMatch(s); found {
				return []ir.Finding{{
					RuleID:      "AEGIS-AWS-856",
					Title:       (ec2EOLImage{}).Title(),
					Description: (ec2EOLImage{}).Description(),
					Severity:    ir.SeverityHigh,
					Resource:    r.Address(),
					Evidence: ir.Evidence{
						Attribute: "name_regex",
						Span:      evidenceSpan(v.Span, r.Span),
						Actual:    "AMI lookup selects " + osName + " (end of life)",
						Expected:  "AMI lookup selecting a supported image",
					},
				}}
			}
		}
	}
	return nil
}

// EOLImageRules returns the end-of-life OS image rules.
func EOLImageRules() []ir.Rule {
	return []ir.Rule{ec2EOLImage{}}
}
