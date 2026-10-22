// Package rules — compliance framework mappings.
//
// ComplianceFor maps rule IDs to the compliance-framework controls they
// violate. Mappings are maintained here (not on the rules themselves) so
// the rule pack stays focused on detection and frameworks can evolve
// independently. Only map where the control genuinely applies; when in
// doubt, leave the rule unmapped rather than stretching a control.
//
// Frameworks:
//   - CIS-AWS-1.5     — CIS Amazon Web Services Foundations Benchmark v1.5
//   - CIS-Azure-2.1   — CIS Microsoft Azure Foundations Benchmark v2.1
//   - CIS-GCP-1.3     — CIS Google Cloud Platform Foundation Benchmark v1.3
//   - CIS-Kubernetes-1.8 — CIS Kubernetes Benchmark v1.8
//   - CIS-Docker-1.6  — CIS Docker Benchmark v1.6
//   - NIST-800-53     — NIST Special Publication 800-53 Rev. 5
//   - PCI-DSS-4.0     — PCI Data Security Standard v4.0
//   - ISO-27001-2022  — ISO/IEC 27001:2022 Annex A controls
//   - SOC2            — AICPA SOC 2 Trust Services Criteria (CC series)
//   - HIPAA           — HIPAA Administrative Simplification, 45 CFR Part 164
//
// ISO/SOC 2/HIPAA refs are crosswalked from each rule's NIST 800-53 anchors
// using the standard published correspondences, and are only attached where
// the underlying concept genuinely falls in that framework's scope (e.g.
// HIPAA refs appear only for access-control, audit, integrity,
// authentication, transmission-security, encryption and backup concepts).
package rules

import (
	"sort"

	"aegis/internal/ir"
)

// ComplianceFor returns the compliance-framework controls violated by the
// given rule ID. Unknown rule IDs return nil. The result is deterministic.
func ComplianceFor(ruleID string) []ir.ComplianceRef {
	refs, ok := complianceMap[ruleID]
	if !ok {
		return nil
	}
	out := make([]ir.ComplianceRef, len(refs))
	copy(out, refs)
	return out
}

// ComplianceFrameworks returns the sorted list of frameworks with mappings.
func ComplianceFrameworks() []string {
	seen := map[string]bool{}
	for _, refs := range complianceMap {
		for _, r := range refs {
			seen[r.Framework] = true
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// HasComplianceFramework reports whether the framework has any mappings.
// Comparison is exact; callers should normalize user input first.
func HasComplianceFramework(framework string) bool {
	for _, f := range ComplianceFrameworks() {
		if f == framework {
			return true
		}
	}
	return false
}

// ComplianceControls returns the sorted distinct control IDs mapped for the
// given framework (e.g. all CIS-AWS-1.5 controls any rule maps to). Used
// for the --compliance pass/fail summary.
func ComplianceControls(framework string) []string {
	seen := map[string]bool{}
	for _, refs := range complianceMap {
		for _, r := range refs {
			if r.Framework == framework {
				seen[r.Control] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// FilterByCompliance returns the findings that map to the given framework,
// with each finding's Compliance field narrowed to that framework's refs.
func FilterByCompliance(findings []ir.Finding, framework string) []ir.Finding {
	var out []ir.Finding
	for _, f := range findings {
		var refs []ir.ComplianceRef
		for _, r := range ComplianceFor(f.RuleID) {
			if r.Framework == framework {
				refs = append(refs, r)
			}
		}
		if len(refs) == 0 {
			continue
		}
		f.Compliance = refs
		out = append(out, f)
	}
	return out
}

// EnrichCompliance attaches all mapped compliance refs to each finding.
// Report-time lookup: rules never set Finding.Compliance directly.
func EnrichCompliance(findings []ir.Finding) []ir.Finding {
	for i := range findings {
		findings[i].Compliance = ComplianceFor(findings[i].RuleID)
	}
	return findings
}

func ref(framework, control string) ir.ComplianceRef {
	return ir.ComplianceRef{Framework: framework, Control: control}
}

const (
	cis       = "CIS-AWS-1.5"
	cisazure  = "CIS-Azure-2.1"
	cisgcp    = "CIS-GCP-1.3"
	cisk8s    = "CIS-Kubernetes-1.8"
	cisdocker = "CIS-Docker-1.6"
	nist      = "NIST-800-53"
	pci       = "PCI-DSS-4.0"
	iso       = "ISO-27001-2022"
	soc2      = "SOC2"
	hipaa     = "HIPAA"
)

var complianceMap = map[string][]ir.ComplianceRef{
	// --- Criticals ---
	"AEGIS-AWS-003": { // S3 bucket policy allows public principal
		ref(cis, "2.1.1"), ref(nist, "AC-3"),
		ref(pci, "1.4.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-006": { // IAM policy allows all actions on all resources
		ref(cis, "1.16"), ref(nist, "AC-6"),
		ref(pci, "7.2.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-101": { // IAM role assumable by anyone
		ref(cis, "1.16"), ref(nist, "AC-3"),
		ref(pci, "7.2.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-104": { // Public S3 exfiltration path
		ref(cis, "2.1.1"), ref(nist, "AC-4"),
		ref(pci, "1.4.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.20"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-202": { // Load balancer listener uses plain HTTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},

	// --- Highs: storage encryption ---
	"AEGIS-AWS-001": { // S3 bucket without server-side encryption
		ref(cis, "2.1.1"), ref(nist, "SC-28"),
		ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-007": { // RDS instance without storage encryption
		ref(cis, "2.3.1"), ref(nist, "SC-28"),
		ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-009": { // EBS volume without encryption
		ref(cis, "2.2.1"), ref(nist, "SC-28"),
		ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-301": { // Launch template EBS volumes unencrypted
		ref(cis, "2.2.1"), ref(nist, "SC-28"),
		ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-304": { // EKS cluster without secrets encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-307": { // Lambda function env vars without KMS
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-313": { // DynamoDB table without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-314": { // Redshift cluster unencrypted
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-317": { // EFS file system unencrypted
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-318": { // OpenSearch domain without node-to-node encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-319": { // OpenSearch domain without encryption at rest
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-341": { // SNS topic without KMS encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-342": { // SQS queue without encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-345": { // MSK cluster without encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-350": { // Kinesis stream without encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-351": { // DocumentDB cluster unencrypted
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-352": { // Neptune cluster unencrypted
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-359": { // Aurora cluster unencrypted
		ref(cis, "2.3.1"), ref(nist, "SC-28"),
		ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-361": { // EMR security configuration without at-rest encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-363": { // Athena workgroup without result encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-364": { // Glue data catalog without SSE-KMS encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-366": { // SageMaker notebook instance without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-368": { // FSx Windows file system without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-369": { // FSx Lustre file system without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-411": { // EC2 instance EBS volumes unencrypted
		ref(cis, "2.2.1"), ref(nist, "SC-28"),
		ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-416": { // FSx OpenZFS file system without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-424": { // WorkSpaces volumes unencrypted
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},

	// --- Highs: public exposure / access control ---
	"AEGIS-AWS-002": { // S3 bucket with public ACL
		ref(cis, "2.1.1"), ref(nist, "AC-3"),
		ref(pci, "1.4.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-004": { // Security group ingress open to the world
		ref(cis, "5.2"), ref(nist, "SC-7"),
		ref(pci, "1.4.1"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-011": { // RDS instance publicly accessible
		ref(cis, "2.3.3"), ref(nist, "AC-3"),
		ref(pci, "1.4.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-102": { // IAM managed policy grants administrative access
		ref(cis, "1.16"), ref(nist, "AC-6"),
		ref(pci, "7.2.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-103": { // Public RDS exposure path
		ref(cis, "2.3.3"), ref(nist, "AC-3"),
		ref(pci, "1.4.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-201": { // Load balancer internet-facing
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-205": { // Subnet auto-assigns public IPs
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-206": { // S3 bucket without public access block
		ref(cis, "2.1.5"), ref(nist, "AC-3"),
		ref(pci, "1.4.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-305": { // EKS cluster with public endpoint
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-315": { // Redshift cluster publicly accessible
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-333": { // Inline admin policy attached to role/user/group
		ref(cis, "1.16"), ref(nist, "AC-6"),
		ref(pci, "7.2.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-343": { // SNS topic policy allows public principal
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-344": { // SQS queue policy allows public principal
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-356": { // DMS replication instance publicly accessible
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-372": { // API Gateway v2 CORS allows all origins
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-375": { // EventBridge permission open to all principals
		ref(nist, "AC-3"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-378": { // WAFv2 Web ACL allows all traffic with no rules
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-381": { // ECS service with public IP assignment
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-390": { // IoT policy with overly broad Allow statement
		ref(nist, "AC-6"), ref(pci, "7.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-399": { // RAM resource share allows external principals
		ref(nist, "AC-3"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-403": { // API Gateway method without authorization
		ref(nist, "IA-2"), ref(iso, "A.5.17"),
		ref(iso, "A.8.5"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-404": { // API Gateway v2 route without authorization
		ref(nist, "IA-2"), ref(iso, "A.5.17"),
		ref(iso, "A.8.5"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-406": { // Lambda permission grants invoke to everyone
		ref(nist, "AC-3"), ref(pci, "7.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-407": { // Lambda function URL without authorization
		ref(nist, "IA-2"), ref(iso, "A.5.17"),
		ref(iso, "A.8.5"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-408": { // ECR repository policy allows public principal
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-414": { // S3 account public access block disabled
		ref(cis, "2.1.5"), ref(nist, "AC-3"),
		ref(pci, "1.4.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-415": { // EFS file system policy allows public principal
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-420": { // KMS key policy allows public principal
		ref(nist, "AC-3"), ref(nist, "IA-5"),
		ref(nist, "SC-12"), ref(nist, "SC-7"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(iso, "A.5.17"), ref(iso, "A.8.24"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"), ref(hipaa, "164.312(d)"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-421": { // Cognito identity pool allows unauthenticated identities
		ref(nist, "IA-2"), ref(iso, "A.5.17"),
		ref(iso, "A.8.5"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-422": { // SSO permission set with inline admin policy
		ref(cis, "1.16"), ref(nist, "AC-6"),
		ref(pci, "7.2.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-428": { // ElastiCache user with open access string
		ref(nist, "AC-3"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-431": { // Redshift Serverless workgroup publicly accessible
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-433": { // VPC endpoint with public policy
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-441": { // S3 access point policy allows public principal
		ref(cis, "2.1.1"), ref(nist, "AC-3"),
		ref(pci, "1.4.1"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-444": { // EC2 instance with public IP address
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},

	// --- Highs: encryption in transit ---
	"AEGIS-AWS-324": { // Load balancer listener with weak TLS policy
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-325": { // CloudFront distribution allows HTTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-326": { // API Gateway custom domain with weak TLS
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-329": { // Load balancer target group uses plain HTTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-354": { // MemoryDB cluster without TLS
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-357": { // DMS endpoint without SSL
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-379": { // Transfer server allows plaintext FTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-401": { // Classic ELB with plain-HTTP listener
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-405": { // CloudFront custom origin fetched over plain HTTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-426": { // SNS subscription over plaintext HTTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-436": { // RDS proxy without TLS enforcement
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-443": { // S3 bucket policy does not enforce TLS (SecureTransport)
		ref(cis, "2.1.2"), ref(nist, "SC-8"),
		ref(pci, "4.2.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},

	// --- Highs: keys, secrets, identity ---
	"AEGIS-AWS-335": { // KMS key without rotation
		ref(cis, "3.8"), ref(nist, "SC-12"),
		ref(pci, "3.6.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-338": { // SSM parameter stores plaintext secret
		ref(nist, "SC-28"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-339": { // Hardcoded credentials in resource config
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-410": { // API Gateway API key hardcoded in config
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-425": { // Secrets Manager version with hardcoded secret
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},

	// --- Highs: hardening ---
	"AEGIS-AWS-203": { // Load balancer not dropping invalid headers
		ref(nist, "SC-7"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-204": { // EC2 instance without IMDSv2 enforcement
		ref(nist, "AC-3"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-302": { // ECS task definition with privileged container
		ref(nist, "CM-7"), ref(pci, "2.2.1"),
		ref(iso, "A.8.9"), ref(soc2, "CC6.6"),
		ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-385": { // CodeBuild project with privileged mode
		ref(nist, "CM-7"), ref(pci, "2.2.1"),
		ref(iso, "A.8.9"), ref(soc2, "CC6.6"),
		ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-412": { // ECS task definition with host networking
		ref(nist, "CM-7"), ref(pci, "2.2.1"),
		ref(iso, "A.8.9"), ref(soc2, "CC6.6"),
		ref(soc2, "CC7.1"),
	},

	// --- Highs: logging / audit ---
	"AEGIS-AWS-010": { // CloudTrail without log file validation
		ref(cis, "3.2"), ref(nist, "AU-9"),
		ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-336": { // CloudTrail not multi-region
		ref(cis, "3.1"), ref(nist, "AU-2"),
		ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},

	// --- GCP criticals/highs (NIST-800-53 only; CIS/PCI maps are AWS-specific) ---
	"AEGIS-GCP-145": { // SA key with weak RSA-1024
		ref(nist, "IA-2"), ref(nist, "SC-12"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-146": { // SA impersonation broad grant
		ref(nist, "AC-6"), ref(iso, "A.5.15"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-148": { // Org IAM basic roles
		ref(nist, "AC-3"), ref(nist, "AC-6"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-149": { // Folder IAM basic roles
		ref(nist, "AC-3"), ref(nist, "AC-6"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-152": { // Project IAM Admin grant
		ref(nist, "AC-6"), ref(iso, "A.5.15"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-162": { // Cloud SQL SSL permissive
		ref(nist, "SC-8"), ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(e)(1)"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-167": { // GKE alpha cluster
		ref(nist, "CM-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-GCP-170": { // GKE master open to world
		ref(nist, "AC-3"), ref(nist, "SC-7"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-178": { // Instance template public IP
		ref(nist, "SC-7"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-185": { // GCS bucket IAM public
		ref(nist, "AC-3"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-186": { // GCS default object ACL public
		ref(nist, "AC-3"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-188": { // GCS bucket IAM admin to domain
		ref(nist, "AC-3"), ref(nist, "AC-6"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-190": { // GCS bucket publicly writable
		ref(nist, "AC-3"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-191": { // BigQuery dataset bigquery.admin
		ref(nist, "AC-6"), ref(iso, "A.5.15"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-192": { // BigQuery table IAM public
		ref(nist, "AC-3"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-194": { // BigQuery dataset dataOwner
		ref(nist, "AC-6"), ref(iso, "A.5.15"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-200": { // Cloud Function EOL runtime
		ref(nist, "SI-7"), ref(nist, "CM-7"),
		ref(iso, "A.8.9"), ref(soc2, "CC7.1"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-205": { // Pub/Sub subscription IAM public
		ref(nist, "AC-3"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-214": { // Firewall all ports to world
		ref(nist, "SC-7"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-219": { // SSL weak ciphers
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-226": { // Secret Manager IAM public
		ref(nist, "AC-3"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-227": { // Secret value in TF state
		ref(nist, "SC-28"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-245": { // Redis AUTH string in state
		ref(nist, "SC-28"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-257": { // Artifact Registry over HTTP
		ref(nist, "SC-8"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-GCP-260": { // Artifact Registry IAM public
		ref(nist, "AC-3"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"),
	},

	// --- AWS deep expansion (650-849) ---
	"AEGIS-AWS-650": { // IAM password policy minimum length below 14
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-651": { // IAM password policy does not require uppercase characters
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-652": { // IAM password policy does not require lowercase characters
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-653": { // IAM password policy does not require numbers
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-654": { // IAM password policy does not require symbols
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-655": { // IAM password policy allows password reuse
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-656": { // IAM password maximum age too long or disabled
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-660": { // IAM policy grants sensitive service wildcard on all resources
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-661": { // IAM policy grants iam:PassRole on all resources
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-663": { // IAM password policy has no maximum password age
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-664": { // IAM user has force_destroy enabled
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-665": { // IAM role allows forced policy detach on destroy
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-666": { // IAM policy attachment grants AdministratorAccess
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-667": { // IAM role has no permissions boundary
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-668": { // IAM access key secret not encrypted with pgp_key
		ref(nist, "IA-5"), ref(nist, "SC-12"),
		ref(iso, "A.5.17"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-669": { // IAM role policy attachment grants PowerUserAccess
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-670": { // IAM policy grants iam:* on a scoped resource
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-671": { // IAM policy Allow statement uses NotResource
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-674": { // IAM group named admin should be reviewed
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-675": { // IAM password policy allows reset after expiry
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-676": { // IAM role trust grants sts:TagSession without conditions
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-677": { // IAM policy statement has no Sid
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-678": { // IAM login profile does not force password reset
		ref(cis, "1.8"), ref(nist, "AU-2"),
		ref(nist, "IA-5"), ref(iso, "A.8.15"),
		ref(iso, "A.5.17"), ref(soc2, "CC7.2"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(b)"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-679": { // Production-like IAM role attached to ReadOnlyAccess
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-685": { // EC2 instance with Windows password retrieval enabled
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-686": { // EC2 user_data embeds AWS credentials
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-687": { // Launch template user_data embeds a hardcoded password
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-688": { // Network interface with public IP association
		ref(nist, "SC-7"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-694": { // AMI copy without encryption
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-695": { // EBS snapshot copy without encryption
		ref(nist, "CP-9"), ref(nist, "SC-12"),
		ref(iso, "A.8.13"), ref(iso, "A.8.24"),
		ref(soc2, "CC7.4"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.310(d)(2)(iv)"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-696": { // EC2 root volume without encryption
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-700": { // Aurora Performance Insights without customer-managed KMS key
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-605": { // RDS instance without enhanced monitoring
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-703": { // Aurora cluster skips final snapshot on deletion
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-704": { // Aurora cluster without automated backups
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-705": { // Aurora cluster snapshot shared with other accounts
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-709": { // RDS parameter group without forced SSL
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-710": { // RDS master password not managed by Secrets Manager
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-712": { // Redshift cluster with short snapshot retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-713": { // Redshift cluster snapshots do not copy tags
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-714": { // ElastiCache cluster without snapshot retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-321": { // ElastiCache replication group without at-rest encryption
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-717": { // ElastiCache replication group without snapshot retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-440": { // Neptune cluster without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-720": { // Lambda async invoke config without a failure destination
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-724": { // Lambda permission grants a service principal without source_arn
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-725": { // Lambda code signing policy warns instead of enforcing
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-729": { // Step Functions state machine with logging switched off
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-731": { // Step Functions definition contains a hardcoded password
		ref(cis, "1.8"), ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-733": { // Lambda code signing config without allowed publishers
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-735": { // ECS container without log configuration
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-738": { // EKS cluster control plane logging without audit logs
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-739": { // EKS encryption config not covering Kubernetes secrets
		ref(nist, "AU-2"), ref(nist, "IA-5"),
		ref(nist, "SC-12"), ref(iso, "A.8.15"),
		ref(iso, "A.5.17"), ref(iso, "A.8.24"),
		ref(soc2, "CC7.2"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(b)"), ref(hipaa, "164.312(d)"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-741": { // Load balancer listener with TLS protocol on port 80
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-744": { // Route sending all traffic to an internet gateway
		ref(nist, "SC-7"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-745": { // Default security group with a world-open rule
		ref(nist, "SC-7"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-750": { // ACM certificate using email validation
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-751": { // API Gateway REST API with a public resource policy
		ref(nist, "IA-5"), ref(nist, "SC-7"),
		ref(iso, "A.5.17"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(d)"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-625": { // CloudFront distribution without access logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-754": { // CloudFront viewer certificate with TLS 1.0 minimum
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-756": { // API Gateway stage without a client certificate
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-759": { // Network Firewall without firewall policy change protection
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-760": { // CloudTrail trail is not an organization trail
		ref(cis, "3.1"), ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"),
		ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-761": { // CloudTrail trail without CloudTrail Insights
		ref(cis, "3.1"), ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"),
		ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-762": { // CloudTrail trail logging disabled
		ref(cis, "3.1"), ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"),
		ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-763": { // Config recorder skips global resource types
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-764": { // Config delivery channel without S3 key prefix
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-765": { // Config recorder status disabled
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-766": { // GuardDuty finding publishing disabled
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-767": { // GuardDuty S3 protection disabled
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-769": { // CloudWatch log group with short log retention
		ref(nist, "AU-2"), ref(nist, "CP-9"),
		ref(iso, "A.8.15"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.2"), ref(soc2, "CC7.4"),
		ref(hipaa, "164.312(b)"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-770": { // CloudWatch log group using AWS-managed encryption key
		ref(nist, "AU-2"), ref(nist, "SC-12"),
		ref(iso, "A.8.15"), ref(iso, "A.8.24"),
		ref(soc2, "CC7.2"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(b)"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-771": { // CloudWatch alarm with no alarm actions
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-772": { // SNS topic using AWS-managed encryption key
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-774": { // SNS topic policy grants wildcard actions
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-775": { // SQS queue using AWS-managed encryption key
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-777": { // SQS queue with short message retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-778": { // SQS queue policy grants wildcard actions
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-780": { // KMS key rotation period longer than one year
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-781": { // KMS key with short deletion window
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},

	"AEGIS-AWS-783": { // KMS key without description
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-784": { // KMS external key without key material expiry
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-785": { // KMS key bypasses policy lockout safety check
		ref(nist, "IA-5"), ref(nist, "SC-12"),
		ref(iso, "A.5.17"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-786": { // EBS default encryption uses AWS-managed key
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-787": { // Secrets Manager secret using AWS-managed encryption key
		ref(nist, "IA-5"), ref(nist, "SC-12"),
		ref(iso, "A.5.17"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-788": { // Secrets Manager rotation interval above 30 days
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-789": { // Secrets Manager secret without description
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-790": { // SSM SecureString parameter using default KMS key
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-791": { // SSM StringList parameter stores plaintext secret
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-792": { // SSM document shared publicly
		ref(nist, "SC-7"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-793": { // Secrets Manager secret version with weak placeholder secret
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-794": { // KMS grant with decrypt and retire-grant operations
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-795": { // KMS grant to public grantee principal
		ref(nist, "IA-5"), ref(nist, "SC-12"),
		ref(nist, "SC-7"), ref(iso, "A.5.17"),
		ref(iso, "A.8.24"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(d)"),
		ref(hipaa, "164.312(a)(2)(iv)"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-796": { // Secrets Manager secret policy allows public principal
		ref(nist, "IA-5"), ref(nist, "SC-7"),
		ref(iso, "A.5.17"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(d)"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-798": { // KMS key policy statement without Sid
		ref(nist, "IA-5"), ref(nist, "SC-12"),
		ref(iso, "A.5.17"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
		ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-799": { // Secrets Manager secret with zero recovery window
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-800": { // Bedrock invocation logging without text data delivery
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-801": { // Bedrock guardrail without a content policy
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-802": { // SageMaker notebook instance with direct internet access
		ref(nist, "SC-7"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-805": { // SageMaker domain allowing public internet app access
		ref(nist, "SC-7"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-806": { // EventBridge archive with zero-day retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-807": { // EventBridge Scheduler schedule without a KMS key
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-809": { // MSK cluster without per-topic enhanced monitoring
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-523": { // OpenSearch domain without fine-grained access control (canonical; ex-811)
		ref(nist, "SC-7"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-623": { // OpenSearch domain without audit/search logs (canonical; ex-812)
		ref(nist, "AU-2"), ref(nist, "SC-7"),
		ref(iso, "A.8.15"), ref(iso, "A.8.20"),
		ref(iso, "A.8.22"), ref(soc2, "CC7.2"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(b)"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-813": { // Neptune cluster skipping the final snapshot
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-814": { // Neptune cluster not copying tags to snapshots
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-430": { // DocumentDB cluster without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-816": { // App Runner service without encryption configuration
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-819": { // Glue security configuration without encryption configuration
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-820": { // Athena workgroup without SSE-KMS query result encryption
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-822": { // Kinesis stream without shard-level metrics
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-823": { // Firehose delivery stream without server-side encryption
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-824": { // Timestream scheduled query error reports without SSE-KMS
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-826": { // CloudFront distribution without a response headers policy
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-332": { // API Gateway v2 stage without access logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-832": { // API Gateway v2 domain name with TLS 1.0 security policy
		ref(nist, "IA-5"), ref(nist, "SC-8"),
		ref(pci, "4.2.1"), ref(iso, "A.5.17"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.7"), ref(hipaa, "164.312(d)"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-834": { // Backup vault lock with short minimum retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-835": { // Backup plan rule without a copy action
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-836": { // Backup vault without vault lock configuration
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-839": { // ACM certificate with certificate transparency logging disabled
		ref(nist, "AU-2"), ref(nist, "SC-8"),
		ref(pci, "4.2.1"), ref(iso, "A.8.15"),
		ref(iso, "A.8.24"), ref(soc2, "CC7.2"),
		ref(soc2, "CC6.7"), ref(hipaa, "164.312(b)"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-842": { // ALB listener with an outdated SSL policy
		ref(nist, "IA-5"), ref(nist, "SC-8"),
		ref(pci, "4.2.1"), ref(iso, "A.5.17"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.7"), ref(hipaa, "164.312(d)"),
		ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-843": { // API Gateway account without a CloudWatch logging role
		ref(nist, "AU-2"), ref(nist, "IA-5"),
		ref(iso, "A.8.15"), ref(iso, "A.5.17"),
		ref(soc2, "CC7.2"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(b)"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-847": { // DLM lifecycle policy disabled
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},

	// --- AWS expansion: least privilege / privilege escalation ---
	"AEGIS-AWS-501": { // IAM policy allows privilege escalation (create + attach policy)
		ref(cis, "1.16"), ref(nist, "AC-6"), ref(pci, "7.2.1"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-502": { // IAM policy allows privilege escalation via iam:PassRole on *
		ref(cis, "1.16"), ref(nist, "AC-6"), ref(pci, "7.2.1"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-503": { // IAM policy allows data exfiltration primitives
		ref(nist, "AC-3"), ref(nist, "AC-6"), ref(pci, "7.2.1"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-504": { // IAM permissions management actions allowed on all resources
		ref(nist, "AC-6"), ref(pci, "7.2.1"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-505": { // Write actions allowed on all resources
		ref(nist, "AC-6"), ref(pci, "7.2.1"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-526": { // IAM policy grants sagemaker:* on all resources
		ref(nist, "AC-6"), ref(pci, "7.2.1"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-553": { // IAM policy uses NotAction with Allow effect
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-555": { // IAM group inline policy grants wildcard admin
		ref(cis, "1.16"), ref(nist, "AC-6"), ref(pci, "7.2.1"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-803": { // SageMaker notebook instance with root access enabled
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},

	// --- AWS expansion: secrets and credential hygiene ---
	"AEGIS-AWS-337": { // Secrets Manager rotation interval too long
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-374": { // AppSync API with API-key authentication
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-534": { // Secrets in EC2 user_data
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-535": { // Plaintext password in provisioner connection
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-536": { // Sensitive value exposed in Terraform output
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-537": { // Secret stored in resource tags
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-538": { // Secret in plaintext variable default
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-539": { // Secret in hardcoded local value
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-552": { // IAM access key created without PGP encryption
		ref(nist, "IA-5"), ref(nist, "SC-12"), ref(iso, "A.5.17"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-649": { // Lambda function with plaintext secret in environment variables
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-850": { // Database instance with weak password
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-857": { // Secret in plaintext CloudFormation parameter default
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},

	// --- AWS expansion: authentication ---
	"AEGIS-AWS-311": { // RDS without IAM database authentication
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-334": { // Weak or absent account password policy
		ref(cis, "1.8"), ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-360": { // Aurora cluster without IAM authentication
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-387": { // Cognito user pool without MFA
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-388": { // Cognito user pool with weak password policy
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-389": { // Cognito user pool without advanced security enforcement
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-409": { // CodePipeline webhook without authentication
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-514": { // ElastiCache replication group without auth token
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-522": { // Neptune cluster without IAM database authentication
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-524": { // Redshift cluster uses default master username
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-554": { // IAM role with max session duration over 12 hours
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AWS-640": { // OpenSearch domain without internal user database
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},

	// --- AWS expansion: network boundary and access enforcement ---
	"AEGIS-AWS-005": { // Security group egress open to the world
		ref(nist, "AC-4"), ref(nist, "SC-7"), ref(iso, "A.5.15"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-328": { // Network ACL with open ingress
		ref(nist, "SC-7"), ref(pci, "1.4.1"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-330": { // CloudFront distribution without WAF
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-331": { // Network ACL rule with open ingress
		ref(nist, "SC-7"), ref(pci, "1.4.1"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-362": { // EMR cluster visible to all users
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-397": { // Default security group has ingress rules
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-398": { // VPC peering connection auto-accept enabled
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-413": { // EKS node group with remote SSH access
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-427": { // SageMaker notebook with direct internet access
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-437": { // AppStream fleet with default internet access
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-442": { // VPC endpoint service without acceptance required
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-506": { // Public load balancer without WAF
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-507": { // Search domain outside VPC
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-508": { // Redshift cluster outside VPC
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-509": { // Transfer Server publicly accessible
		ref(nist, "AC-3"), ref(nist, "SC-7"), ref(pci, "1.4.1"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.1"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-511": { // SageMaker notebook not in custom VPC
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-513": { // AppSync API without WAF
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-532": { // SageMaker notebook instance allows IMDSv1
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-533": { // Default security group allows traffic from anywhere
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-541": { // Launch configuration allows IMDSv1
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-556": { // Transit Gateway route table propagation enabled
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-557": { // VPC endpoint policy allows all principals
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-644": { // OpenSearch domain without fine-grained access control
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-680": { // EC2 instance exposes resource tags to IMDS
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-681": { // EC2 IMDS hop limit above 1
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-746": { // Default network ACL with an allow-all rule
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-747": { // VPC endpoint with auto-accept enabled
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-753": { // CloudFront S3 origin without origin access control
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-825": { // CloudFront distribution using legacy origin access identity
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-829": { // API Gateway v2 API with wildcard CORS origins
		ref(nist, "AC-3"), ref(pci, "1.4.1"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AWS-858": { // Security group exposes database port to the internet
		ref(nist, "AC-3"), ref(nist, "SC-7"), ref(pci, "1.4.1"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.1"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},

	// --- AWS expansion: encryption at rest and key management ---
	"AEGIS-AWS-349": { // MQ broker without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-355": { // DAX cluster without encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-365": { // Kinesis Firehose delivery stream without server-side encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-367": { // SageMaker endpoint configuration without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-370": { // SageMaker domain without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-384": { // CodeBuild project with artifacts encryption disabled
		ref(nist, "SC-28"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-386": { // CodePipeline artifact store without KMS encryption
		ref(nist, "SC-28"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-391": { // EBS default encryption disabled
		ref(cis, "2.2.1"), ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-392": { // Backup vault without KMS encryption
		ref(nist, "SC-28"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-395": { // App Runner service without customer-managed encryption
		ref(nist, "SC-28"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-432": { // Redshift Serverless namespace without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-434": { // Glue job without security configuration
		ref(nist, "SC-28"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-435": { // Timestream database without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-515": { // ECR repository without KMS encryption
		ref(nist, "SC-28"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-517": { // EMR security configuration without local disk encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-561": { // KMS key with deletion window under 7 days
		ref(nist, "SC-12"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-562": { // KMS grant with wildcard operations
		ref(nist, "SC-12"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-563": { // Secrets Manager secret without customer-managed KMS key
		ref(nist, "SC-28"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-566": { // RDS Performance Insights without customer-managed KMS key
		ref(nist, "SC-12"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-634": { // RDS Cluster not encrypted with customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-852": { // S3 bucket encrypted with AWS-managed key, no customer-managed key
		ref(nist, "SC-12"), ref(pci, "3.6.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-853": { // DocumentDB cluster encrypted with AWS-managed key, no customer-managed key
		ref(nist, "SC-12"), ref(pci, "3.6.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-854": { // Neptune cluster encrypted with AWS-managed key, no customer-managed key
		ref(nist, "SC-12"), ref(pci, "3.6.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-855": { // EBS volume encrypted with AWS-managed key, no customer-managed key
		ref(nist, "SC-12"), ref(pci, "3.6.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},

	// --- AWS expansion: encryption in transit ---
	"AEGIS-AWS-320": { // ElastiCache replication group without transit encryption
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-510": { // Load balancer listener without HTTP-to-HTTPS redirect
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-516": { // EMR security configuration without in-transit encryption
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-518": { // DAX cluster without TLS encryption
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-519": { // Search domain with outdated TLS security policy
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-520": { // Transfer Server with outdated security policy
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-637": { // Elasticsearch/OpenSearch domain without HTTPS enforcement
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-808": { // MSK cluster allowing plaintext client-broker traffic
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-841": { // Load balancer target group with plaintext HTTP health checks
		ref(nist, "SC-8"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AWS-849": { // Transfer Family server with plaintext FTP enabled
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},

	// --- AWS expansion: logging, monitoring and audit protection ---
	"AEGIS-AWS-209": { // VPC without flow logs
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-306": { // EKS cluster without control plane logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-308": { // Lambda without active X-Ray tracing
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-310": { // EC2 instance without detailed monitoring
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-316": { // Redshift cluster without audit logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-327": { // API Gateway stage without access logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-340": { // CloudTrail without global service events
		ref(cis, "3.1"), ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-346": { // CloudWatch log group without KMS encryption
		ref(nist, "AU-9"), ref(nist, "SC-28"), ref(iso, "A.8.15"), ref(iso, "A.8.24"),
		ref(soc2, "CC7.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(b)"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-347": { // CloudWatch log group without retention
		ref(nist, "AU-9"), ref(iso, "A.8.15"), ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-348": { // GuardDuty detector disabled
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-371": { // Load balancer without access logs
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-373": { // AppSync API without X-Ray tracing
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-376": { // Step Functions state machine without logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-377": { // Step Functions state machine without X-Ray tracing
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-380": { // Transfer server without CloudWatch logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-383": { // ECS cluster without Container Insights
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-393": { // Config recorder not recording all resources
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-402": { // Classic ELB without access logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-445": { // S3 bucket without server access logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-543": { // RDS instance without CloudWatch log exports
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-568": { // CloudTrail trail without KMS encryption
		ref(nist, "AU-9"), ref(nist, "SC-28"), ref(pci, "10.3.1"), ref(iso, "A.8.15"), ref(iso, "A.8.24"),
		ref(soc2, "CC7.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(b)"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AWS-570": { // CloudTrail S3 bucket without MFA delete protection
		ref(nist, "AU-9"), ref(iso, "A.8.15"), ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-607": { // RDS Postgres instance without query logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-608": { // RDS instance without Performance Insights
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-609": { // Load balancer without access logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-610": { // CloudWatch log group without retention period
		ref(nist, "AU-9"), ref(iso, "A.8.15"), ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-611": { // Neptune cluster without CloudWatch log exports
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-613": { // WAFv2 web ACL without logging configuration
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-614": { // AppSync GraphQL API without logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-615": { // MQ broker without audit logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-617": { // CodeBuild project without logging configuration
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-618": { // Elasticsearch domain without audit logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-620": { // MQ broker without general logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-622": { // MSK cluster without logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-624": { // DocumentDB cluster without CloudWatch log exports
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-631": { // RDS Cluster without audit logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-635": { // RDS Cluster without Performance Insights
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-636": { // RDS Cluster without enhanced monitoring
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-642": { // Elasticsearch/OpenSearch domain without slow logs
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-647": { // Lambda function without dead-letter queue
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-730": { // Step Functions state machine with X-Ray tracing disabled
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-740": { // WAF web ACL with sampled requests disabled
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-755": { // API Gateway stage without X-Ray tracing
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-779": { // SNS subscription without dead-letter queue
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AWS-851": { // CloudTrail trail without CloudWatch Logs integration
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},

	// --- AWS expansion: backup, recovery and deletion protection ---
	"AEGIS-AWS-008": { // RDS instance without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-012": { // S3 bucket without versioning
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-207": { // RDS instance without backup retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-208": { // ElastiCache replication group without snapshots
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-312": { // DynamoDB table without point-in-time recovery
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-322": { // Aurora cluster without backup retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-323": { // Load balancer without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-353": { // DocumentDB cluster without backup retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-358": { // Aurora cluster without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-417": { // DynamoDB table without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-429": { // Neptune cluster without backup retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-438": { // Network Firewall without delete protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-439": { // MemoryDB cluster without snapshot retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-446": { // RDS instance without Multi-AZ
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-551": { // ElastiCache replication group without Multi-AZ / failover
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-612": { // Neptune cluster without adequate backup retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-626": { // DocumentDB cluster without adequate backup retention
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-632": { // Aurora cluster without backtracking enabled
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-641": { // Elasticsearch/OpenSearch domain without snapshot configuration
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-683": { // EC2 instance without termination protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-707": { // RDS subnet group with a single subnet
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AWS-716": { // ElastiCache replication group without automatic failover
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},

	// --- AWS expansion: hardening and configuration enforcement ---
	"AEGIS-AWS-419": { // Athena workgroup configuration not enforced
		ref(nist, "CM-6"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-527": { // ECS container without read-only root filesystem
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-734": { // ECS task definition sharing host PID or IPC namespace
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-736": { // ECS service with ECS Exec enabled
		ref(nist, "CM-7"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-818": { // Batch job definition running privileged containers
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-821": { // Athena workgroup not enforcing workgroup configuration
		ref(nist, "CM-6"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"),
	},

	// --- AWS expansion: flaw remediation and software integrity ---
	"AEGIS-AWS-303": { // ECR repository without image scanning
		ref(nist, "SI-2"), ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-394": { // Beanstalk environment without managed platform updates
		ref(nist, "SI-2"), ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-521": { // ECR repository allows mutable image tags
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-AWS-530": { // WAF web ACL without Log4j protection rule
		ref(nist, "SI-2"), ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-531": { // CloudFront WAF web ACL without Log4j AWS managed rule
		ref(nist, "SI-2"), ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-544": { // RDS instance without auto minor version upgrades
		ref(nist, "SI-2"), ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-643": { // Elasticsearch/OpenSearch domain on an end-of-life engine version
		ref(nist, "SI-2"), ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-645": { // Lambda function without code signing
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-AWS-648": { // Lambda function on an end-of-life runtime
		ref(nist, "SI-2"), ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-711": { // Redshift cluster without automatic version upgrades
		ref(nist, "SI-2"), ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AWS-721": { // Lambda function deployed from a mutable container image tag
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-AWS-856": { // EC2 instance on end-of-life OS image
		ref(nist, "SI-2"), ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	// --- Azure: public / anonymous access ---
	"AEGIS-AZR-001": { // Storage account allows public blob access
		ref(cisazure, "3.5"), ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-122": { // Storage blobs allow public access
		ref(cisazure, "3.5"), ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-139": { // App Service CORS allows any origin
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-143": { // App Service CORS allows credentials
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-195": { // Storage account allows nested public items
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-197": { // Storage container with public access
		ref(cisazure, "3.5"), ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-252": { // Container Registry with anonymous pull enabled
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},

	// --- Azure: network boundary / public network exposure ---
	"AEGIS-AZR-003": { // NSG rule open to the internet
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-006": { // Storage account with public network access
		ref(cisazure, "3.5"), ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-010": { // NSG rule open to the internet on a sensitive port
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-015": { // AKS cluster without network policy
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-021": { // Storage account network rules allow all
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-023": { // Application Gateway without WAF
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-039": { // Key Vault with public network access
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-050": { // MSSQL firewall rule allows all IPs
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-053": { // NSG rule allows RDP from the internet
		ref(cisazure, "6.1"), ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-054": { // NSG rule allows SSH from the internet
		ref(cisazure, "6.2"), ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-055": { // NSG rule allows all destination ports from the internet
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-059": { // Subnet without network security group
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-069": { // AKS cluster with public API server
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-079": { // Network interface with public IP on VM subnet
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-081": { // CosmosDB account without IP range filter
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-084": { // CosmosDB account with public network access
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-087": { // Container Registry without network restrictions
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-090": { // Container Registry with public network access
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-099": { // Front Door without WAF policy
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-106": { // MSSQL server allows public network access
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-137": { // App Service without IP access restrictions
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-138": { // App Service SCM site without access restrictions
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-142": { // App Service IP restriction allows all traffic
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-148": { // Storage account with public network access (default)
		ref(cisazure, "3.5"), ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-149": { // Storage account without network rules
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-151": { // Function App without IP restrictions
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-154": { // API Management with public network access enabled
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-155": { // Data Factory with public network access enabled
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-156": { // Synapse workspace without managed virtual network
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-159": { // Databricks workspace with public network access enabled
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-160": { // Event Grid topic with public network access enabled
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-162": { // Machine Learning workspace with public network access enabled
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-164": { // App Configuration with public network access enabled
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-165": { // Automation account with public network access enabled
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-166": { // Search service with public network access enabled
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-167": { // Cognitive Services account with public network access enabled
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-168": { // IoT Hub with public network access enabled
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-169": { // PostgreSQL flexible server with public network access enabled
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-187": { // Key Vault network ACLs allow public traffic
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-199": { // Storage network rules allow public traffic
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-205": { // Key Vault firewall without IP rules
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-207": { // SQL firewall rule open to the internet
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-208": { // Legacy SQL firewall rule open to the internet
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-209": { // SQL Managed Instance with public data endpoint enabled
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-214": { // App Service without IP restrictions
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-219": { // Windows Web App without IP restrictions
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-222": { // Linux Web App without IP restrictions
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-224": { // App Service deployment slot without IP restrictions
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-226": { // AKS cluster with HTTP application routing enabled
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-229": { // AKS API server exposed without authorized IP ranges
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-236": { // Azure Firewall threat intelligence not in deny mode
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-238": { // Front Door WAF policy not in prevention mode
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-239": { // Application Gateway without WAF enabled
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-244": { // NSG inline security rule open to the internet
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-249": { // Log Analytics workspace with public ingestion
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-250": { // Log Analytics workspace with public query access
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-253": { // Container Registry network rules allow public traffic
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-255": { // Container Registry with public network access enabled
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-263": { // Cosmos DB account with public network access enabled
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-267": { // Event Hub namespace with public network access enabled
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-271": { // Service Bus namespace with public network access enabled
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-273": { // Service Bus namespace without network rule set
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-281": { // Event Hub namespace without network rule set
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-282": { // Front Door WAF policy without managed rule set
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-300": { // Data Factory without managed virtual network
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-304": { // Databricks workspace with public IPs on clusters
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-305": { // IoT Hub with public access and no IP filter
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-309": { // Cognitive Services with permissive network ACLs
		ref(nist, "SC-7"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-313": { // Redis cache with public network access enabled
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},

	// --- Azure: encryption in transit / TLS ---
	"AEGIS-AZR-002": { // Storage account below TLS 1.2
		ref(cisazure, "3.13"), ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-011": { // App Service without HTTPS-only
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-012": { // App Service below TLS 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-019": { // Redis cache with non-SSL port enabled
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-020": { // Redis cache below TLS 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-022": { // Database server without SSL enforcement
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-026": { // Storage account allows HTTP traffic
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-035": { // Storage account NFSv3 without secure transfer requirement
		ref(nist, "SC-8"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-064": { // App Service FTPS allows plaintext FTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-067": { // App Service slot without HTTPS-only
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-068": { // App Service with minimum TLS below 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-096": { // PostgreSQL server without SSL enforcement
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-097": { // MySQL server without SSL enforcement
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-098": { // MariaDB server without SSL enforcement
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-105": { // MSSQL server not using TLS 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-113": { // App Service with FTP enabled (not restricted to FTPS)
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-121": { // Storage account not using latest TLS version
		ref(cisazure, "3.13"), ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-150": { // Function App without HTTPS-only
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-210": { // SQL Managed Instance below TLS 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-211": { // App Service with FTPS enabled
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-216": { // App Service deployment slot without HTTPS-only
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-217": { // Windows Web App with FTPS enabled
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-218": { // Windows Web App below TLS 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-220": { // Linux Web App with FTPS enabled
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-221": { // Linux Web App below TLS 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-240": { // Application Gateway below TLS 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-264": { // Cosmos DB account below TLS 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-266": { // Event Hub namespace below TLS 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-270": { // Service Bus namespace below TLS 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-275": { // API Management API allowing plain HTTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-284": { // Front Door backend pool with weak minimum TLS
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-285": { // Front Door without HTTP-to-HTTPS redirect rule
		ref(nist, "SC-8"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-286": { // CDN endpoint without HTTPS
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-287": { // CDN endpoint with weak minimum TLS
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-AZURE-307": { // IoT Hub below TLS 1.2
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},

	// --- Azure: encryption at rest ---
	"AEGIS-AZURE-018": { // SQL database without transparent data encryption
		ref(cisazure, "4.1.2"), ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-032": { // Storage account without infrastructure encryption
		ref(cisazure, "3.1"), ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-044": { // MSSQL server without transparent data encryption
		ref(cisazure, "4.1.2"), ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-049": { // MSSQL database without transparent data encryption
		ref(cisazure, "4.1.2"), ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-074": { // AKS cluster without disk encryption set
		ref(nist, "SC-28"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-077": { // Virtual machine OS disk without encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-133": { // AKS node pool without host encryption
		ref(nist, "SC-28"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-293": { // Automation variable stored unencrypted
		ref(nist, "SC-28"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-294": { // Virtual machine without encryption at host
		ref(nist, "SC-28"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-303": { // Databricks workspace without infrastructure encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},

	// --- Azure: key management / customer-managed keys ---
	"AEGIS-AZR-005": { // Key Vault without purge protection
		ref(cisazure, "8.5"), ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-033": { // Storage account without customer-managed key
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-037": { // Key Vault without soft delete
		ref(cisazure, "8.5"), ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-040": { // Key Vault secret without expiration date
		ref(cisazure, "8.2"), ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-041": { // Key Vault key without rotation policy
		ref(nist, "SC-12"), ref(pci, "3.6.1"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-085": { // CosmosDB account without customer-managed key
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-094": { // Event Hub namespace without customer-managed key
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-095": { // Service Bus namespace without customer-managed key
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-158": { // Databricks workspace without customer-managed key
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-186": { // Key Vault soft-delete retention under 90 days
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-189": { // Key Vault key not HSM-backed
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-200": { // Key Vault key without expiration date
		ref(cisazure, "8.1"), ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-257": { // Container Registry without customer-managed key
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-259": { // Log Analytics workspace without customer-managed key
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-289": { // Recovery Services vault without customer-managed key
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-299": { // Data Factory without customer-managed key
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-302": { // Synapse workspace without customer-managed key
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-AZURE-310": { // Cognitive Services account without customer-managed key
		ref(nist, "SC-12"),
		ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},

	// --- Azure: least privilege / privileged access ---
	"AEGIS-AZURE-014": { // AKS cluster without RBAC
		ref(nist, "AC-6"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-016": { // Container Registry with admin user enabled
		ref(nist, "AC-6"), ref(pci, "7.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-038": { // Key Vault not using RBAC authorization
		ref(nist, "AC-6"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-127": { // AKS cluster with local admin accounts enabled
		ref(nist, "AC-6"), ref(pci, "7.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-128": { // AKS cluster without Azure AD RBAC integration
		ref(nist, "AC-6"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-171": { // Owner role assignment
		ref(nist, "AC-6"), ref(pci, "7.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-172": { // Custom role definition with wildcard actions
		ref(nist, "AC-6"), ref(pci, "7.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-173": { // Contributor role assigned at subscription scope
		ref(nist, "AC-6"), ref(pci, "7.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-174": { // Key Vault access policy with wildcard permissions
		ref(nist, "AC-6"), ref(pci, "7.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-269": { // Event Hub authorization rule with manage rights
		ref(nist, "AC-6"), ref(pci, "7.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-306": { // IoT Hub shared access policy with registry write
		ref(nist, "AC-6"), ref(pci, "7.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},

	// --- Azure: authentication / managed identity ---
	"AEGIS-AZURE-061": { // App Service without authentication
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-062": { // App Service without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-072": { // AKS cluster without pod-managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-078": { // Virtual machine without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-107": { // MSSQL server without Azure AD authentication
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-116": { // App Service without system-assigned managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-152": { // Function App without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-170": { // Conditional Access policy not enforced
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-177": { // API Management without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-179": { // Linux Web App without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-180": { // SQL server without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-181": { // Storage account without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-182": { // Data Factory without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-183": { // Synapse workspace without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-184": { // Cosmos DB account without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-185": { // Event Hub namespace without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-274": { // API Management API without subscription requirement
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-292": { // Automation account without managed identity
		ref(nist, "IA-2"),
		ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},

	// --- Azure: authenticators / keys / local authentication ---
	"AEGIS-AZURE-024": { // Linux VM with password authentication
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-031": { // Storage account allows shared key access
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-125": { // Storage account without SAS expiry policy
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-161": { // Event Grid topic with local authentication enabled
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-176": { // Entra ID user with hardcoded password
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-192": { // Storage account not defaulting to OAuth authentication
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-194": { // Storage SAS policy not blocking expired tokens
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-256": { // Container Registry task exposing secrets in commands
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-265": { // Cosmos DB account with local authentication enabled
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-268": { // Event Hub namespace with local authentication enabled
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-272": { // Service Bus namespace with local authentication enabled
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-311": { // Cognitive Services account with local authentication
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-AZURE-314": { // SQL server administrator with weak password
		ref(nist, "IA-5"),
		ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},

	// --- Azure: logging / auditing / monitoring ---
	"AEGIS-AZURE-034": { // Storage account queue without logging
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-046": { // MSSQL server without security alert policy
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-071": { // AKS cluster without container insights
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-091": { // Monitor log profile without categories
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-101": { // MSSQL server without auditing enabled
		ref(cisazure, "4.2.1"), ref(nist, "AU-2"), ref(pci, "10.3.1"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-103": { // MSSQL threat detection not set to all types
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-111": { // App Service without detailed error messages
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-112": { // App Service without failed request tracing
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-114": { // App Service without HTTP logging
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-130": { // AKS cluster without Microsoft Defender for Containers
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-141": { // App Service without application logs
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-235": { // NSG flow log disabled
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-246": { // Defender for Cloud plan not Standard tier
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-260": { // Defender for Resource Manager plan not enabled
		ref(nist, "AU-2"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-017": { // Monitor log profile without retention
		ref(nist, "AU-9"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-056": { // NSG without flow log retention configured
		ref(nist, "AU-9"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-092": { // Monitor log profile with short retention
		ref(nist, "AU-9"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-093": { // Application Insights with short retention
		ref(nist, "AU-9"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-102": { // MSSQL auditing retention less than 90 days
		ref(nist, "AU-9"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-248": { // Log Analytics workspace retention under 90 days
		ref(nist, "AU-9"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-AZURE-258": { // Application Insights retention under 90 days
		ref(nist, "AU-9"),
		ref(iso, "A.8.15"), ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},

	// --- Azure: backup / recovery / deletion protection ---
	"AEGIS-AZURE-013": { // CosmosDB account without explicit backup policy
		ref(nist, "CP-9"),
		ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AZURE-028": { // Storage account without blob versioning
		ref(nist, "CP-9"),
		ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AZURE-029": { // Storage account without blob soft delete
		ref(nist, "CP-9"),
		ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AZURE-030": { // Storage account without container soft delete
		ref(nist, "CP-9"),
		ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AZURE-052": { // MSSQL database with short backup retention
		ref(nist, "CP-9"),
		ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AZURE-082": { // CosmosDB account without backup configuration
		ref(nist, "CP-9"),
		ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AZURE-140": { // App Service without backup configuration
		ref(nist, "CP-9"),
		ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AZURE-163": { // App Configuration without purge protection
		ref(nist, "CP-9"),
		ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AZURE-262": { // Cosmos DB account without continuous backup
		ref(nist, "CP-9"),
		ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-AZURE-288": { // Recovery Services vault without soft delete
		ref(nist, "CP-9"),
		ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},

	// --- Azure: information flow / data exfiltration ---
	"AEGIS-AZURE-145": { // Storage account allows cross-tenant replication
		ref(nist, "AC-4"),
		ref(iso, "A.5.15"), ref(iso, "A.8.20"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-157": { // Synapse workspace without data exfiltration protection
		ref(nist, "AC-4"),
		ref(iso, "A.5.15"), ref(iso, "A.8.20"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-237": { // Bastion host with clipboard access enabled
		ref(nist, "AC-4"),
		ref(iso, "A.5.15"), ref(iso, "A.8.20"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-AZURE-301": { // Synapse workspace allowing data exfiltration
		ref(nist, "AC-4"),
		ref(iso, "A.5.15"), ref(iso, "A.8.20"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},

	// --- Azure: hardening / least functionality ---
	"AEGIS-AZURE-065": { // App Service with remote debugging enabled
		ref(nist, "CM-7"),
		ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AZURE-231": { // AKS cluster with run command enabled
		ref(nist, "CM-7"),
		ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},

	// --- Azure: patching / flaw remediation ---
	"AEGIS-AZURE-073": { // AKS cluster without automatic upgrades
		ref(nist, "SI-2"),
		ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AZURE-080": { // Virtual machine without automatic OS patching
		ref(nist, "SI-2"),
		ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AZURE-132": { // AKS node pool without node OS auto-upgrade channel
		ref(nist, "SI-2"),
		ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AZURE-135": { // AKS cluster without automatic upgrade channel
		ref(nist, "SI-2"),
		ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-AZURE-228": { // AKS cluster without node OS auto-upgrade
		ref(nist, "SI-2"),
		ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},

	// --- Azure: integrity / signing / boot ---
	"AEGIS-AZURE-088": { // Container Registry without content trust
		ref(nist, "SI-7"),
		ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-AZURE-251": { // Container Registry without content trust
		ref(nist, "SI-7"),
		ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-AZURE-290": { // Recovery Services vault without immutability
		ref(nist, "SI-7"),
		ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-AZURE-295": { // Virtual machine without secure boot
		ref(nist, "SI-7"),
		ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},

	// ------------------------------------------------------------------
	// --- GCP expansion: public exposure & access control ---
	"AEGIS-GCP-001": { // GCS bucket publicly readable via IAM
		ref(cisgcp, "5.1"), ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-005": { // GCS bucket without uniform bucket-level access
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-013": { // Cloud Function with public ingress
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-026": { // GCS bucket with public canned ACL
		ref(cisgcp, "5.1"), ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-028": { // GCS bucket with website hosting enabled
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-029": { // GCS bucket CORS allows any origin
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-032": { // GCS bucket without public access prevention
		ref(cisgcp, "5.1"), ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-033": { // BigQuery dataset with public access
		ref(cisgcp, "7.1"), ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-038": { // BigQuery IAM grants data access to the public
		ref(cisgcp, "7.1"), ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-041": { // Cloud SQL user allows connections from any host
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-076": { // Project IAM grants role to the public
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-077": { // Service account IAM grants to the public
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-082": { // KMS key IAM grants to the public
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-096": { // Pub/Sub topic IAM grants to the public
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-097": { // Cloud Run service allows public invocation
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-100": { // Cloud Function source code in public bucket
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-263": { // API Gateway API config without managed service config
		ref(nist, "AC-3"), ref(nist, "IA-2"), ref(iso, "A.5.15"), ref(iso, "A.5.17"),
		ref(iso, "A.8.3"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"),
		ref(hipaa, "164.312(a)(1)"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-284": { // Cloud CDN backend bucket without signed URLs
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},

	// --- GCP expansion: least privilege & IAM grants ---
	"AEGIS-GCP-009": { // GKE cluster with legacy ABAC enabled
		ref(nist, "AC-3"), ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-018": { // Compute instance with overly broad service-account scope
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-036": { // BigQuery dataset access with primitive role
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-053": { // GKE node pool with default service account and broad scopes
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-062": { // Compute instance with default service account
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-072": { // Project IAM binding grants Owner role
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-073": { // Project IAM binding grants Editor role
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-074": { // Project IAM grants Viewer to individual user
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-078": { // Custom IAM role with wildcard permissions
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-083": { // KMS admin role granted to individual user
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-099": { // Cloud Run service with default service account
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-131": { // Cloud Build trigger with default service account
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-203": { // Cloud Run service with explicit default compute service account
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-268": { // Dataflow job with default service account
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},

	// --- GCP expansion: encryption at rest (CMEK) ---
	"AEGIS-GCP-006": { // BigQuery dataset without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-020": { // Pub/Sub topic without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-025": { // GCS bucket without customer-managed encryption
		ref(cisgcp, "5.2"), ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-035": { // BigQuery table without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-061": { // Compute instance boot disk without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-066": { // Compute persistent disk without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-125": { // Memorystore Redis without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-126": { // Spanner database without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-127": { // Artifact Registry repository without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-132": { // Dataflow job without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-133": { // Dataproc cluster without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-134": { // Composer environment without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-138": { // Secret Manager user-managed replication without CMEK
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-140": { // Filestore instance without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-165": { // GKE cluster without application-layer secrets encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-172": { // GKE node boot disks without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-181": { // Compute snapshot without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-182": { // Compute image without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-252": { // Firestore database without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-255": { // Bigtable cluster without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-264": { // Apigee organization without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-275": { // Vertex AI dataset without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-277": { // Vertex AI featurestore without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-278": { // Vertex AI tensorboard without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-279": { // Vertex AI metadata store without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},

	// --- GCP expansion: encryption in transit & cryptographic strength ---
	"AEGIS-GCP-008": { // Cloud SQL instance without SSL enforcement
		ref(cisgcp, "6.1"), ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-GCP-093": { // DNSSEC with weak signing algorithm
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-124": { // Memorystore Redis without in-transit encryption
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-GCP-136": { // SSL policy below TLS 1.2
		ref(nist, "SC-8"), ref(nist, "SC-12"), ref(pci, "4.2.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(a)(2)(iv)"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-GCP-142": { // VPN tunnel using IKEv1
		ref(nist, "SC-8"), ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(soc2, "CC6.7"),
		ref(hipaa, "164.312(a)(2)(iv)"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-GCP-189": { // GCS bucket CORS allows insecure HTTP origin
		ref(nist, "SC-8"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-GCP-212": { // SSL policy with COMPATIBLE profile
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-213": { // Backend service with plaintext HTTP protocol
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-GCP-266": { // API Gateway API config with insecure HTTP server URLs
		ref(nist, "SC-8"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},

	// --- GCP expansion: network boundary & segmentation ---
	"AEGIS-GCP-002": { // Firewall rule open to the world
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-004": { // GKE cluster without master authorized networks
		ref(nist, "AC-3"), ref(nist, "SC-7"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.1"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-007": { // Cloud SQL instance with public IP
		ref(cisgcp, "6.2"), ref(nist, "AC-3"), ref(nist, "SC-7"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-011": { // GKE cluster not private
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-014": { // Firewall rule open to SSH from the internet
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-015": { // Backend service without Cloud Armor policy
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-017": { // Compute instance with public IP
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-023": { // Subnetwork without private Google access
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-040": { // Cloud SQL instance allows connections from the internet
		ref(cisgcp, "6.2"), ref(nist, "AC-3"), ref(nist, "SC-7"), ref(iso, "A.5.15"),
		ref(iso, "A.8.3"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.1"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-057": { // Compute instance with IP forwarding enabled
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-067": { // Firewall allows RDP from the internet
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-068": { // Firewall allows all ports from the internet
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-070": { // Firewall allows all protocols
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-071": { // Firewall egress rule allows all destinations
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-088": { // Project auto-creates the default network
		ref(cisgcp, "3.1"), ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-111": { // GKE cluster without network policy enforcement
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-113": { // GKE control plane publicly reachable
		ref(nist, "AC-3"), ref(nist, "SC-7"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.1"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-130": { // Cloud Run v2 service with internet ingress
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-168": { // GKE cluster without VPC-native networking
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-169": { // GKE cluster allows external IPs for Kubernetes services
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-197": { // Cloud Run service without VPC access
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-201": { // Cloud Function (2nd gen) without VPC connector
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-216": { // Subnetwork with external IPv6 access
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-217": { // Subnetwork without Private Google Access setting
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-221": { // VPC network with auto-created subnetworks
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-265": { // Apigee CLOUD runtime organization without authorized network
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-267": { // Dataflow job without private IP configuration
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-270": { // Dataproc cluster without internal IP only
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-273": { // Composer environment without private environment
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-274": { // Composer environment with public web server
		ref(nist, "AC-3"), ref(nist, "SC-7"), ref(iso, "A.5.15"), ref(iso, "A.8.3"),
		ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.1"), ref(soc2, "CC6.6"),
		ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-276": { // Vertex AI endpoint without Private Service Connect
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-GCP-286": { // Cloud CDN backend bucket without edge security policy
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"),
		ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},

	// --- GCP expansion: logging, audit & log protection ---
	"AEGIS-GCP-021": { // GKE cluster without logging and monitoring
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-027": { // GCS bucket without access logging
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-046": { // Cloud SQL instance without log_disconnections
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-069": { // Firewall rule without flow logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-079": { // Project IAM policy without audit config
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-085": { // Logging sink without unique writer identity
		ref(nist, "AU-9"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-086": { // Audit config exempts the public from logging
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-087": { // Project without data-access audit logging
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-091": { // DNS policy without query logging
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-101": { // Cloud SQL PostgreSQL without log_checkpoints
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-102": { // Cloud SQL PostgreSQL without log_connections
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-103": { // Cloud SQL PostgreSQL without log_disconnections
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-104": { // Cloud SQL PostgreSQL without log_lock_waits
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-105": { // Cloud SQL PostgreSQL without log_duration
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-106": { // Cloud SQL PostgreSQL without pgAudit logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-107": { // Cloud SQL PostgreSQL log_min_messages not set appropriately
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-115": { // GKE cluster with Stackdriver logging disabled
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-120": { // Compute subnetwork without VPC flow logs
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-137": { // Backend service without logging
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-139": { // Logging sink disabled
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-218": { // Cloud NAT without logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-232": { // Logging sink filter excludes security logs
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-233": { // Log bucket without retention or unlocked retention
		ref(nist, "AU-9"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-234": { // Log bucket without customer-managed encryption
		ref(nist, "AU-9"), ref(nist, "SC-28"), ref(iso, "A.8.15"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(soc2, "CC7.3"),
		ref(hipaa, "164.312(a)(2)(iv)"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-235": { // Log bucket with retention under 30 days
		ref(nist, "AU-9"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-236": { // Log bucket retention not locked
		ref(nist, "AU-9"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-239": { // Logging exclusion excludes everything
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-GCP-240": { // Folder/organization/billing logging sink disabled
		ref(nist, "AU-2"), ref(pci, "10.3.1"), ref(iso, "A.8.15"),
		ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},

	// --- GCP expansion: backup, recovery & deletion protection ---
	"AEGIS-GCP-003": { // Cloud SQL instance without automated backups
		ref(cisgcp, "6.3"), ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-016": { // GCS bucket without versioning
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-019": { // Cloud SQL instance without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-037": { // BigQuery dataset without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-039": { // Cloud SQL instance without point-in-time recovery
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-064": { // Compute instance without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-129": { // Cloud Run v2 service without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-156": { // Cloud SQL backup retention below 7 days
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-159": { // Cloud SQL transaction log retention below 7 days
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-160": { // Cloud SQL MySQL instance without binary logging
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-183": { // GCS bucket without soft-delete protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-193": { // BigQuery table without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-247": { // Spanner instance with automatic backups disabled
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-248": { // Spanner database with version retention under 1 hour
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-249": { // Spanner database without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-250": { // Spanner database without drop protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-253": { // Firestore database with delete protection disabled
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-254": { // Firestore database without point-in-time recovery
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-256": { // Bigtable instance without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-GCP-288": { // Filestore instance without deletion protection
		ref(nist, "CP-9"), ref(iso, "A.8.13"),
		ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},

	// --- GCP expansion: authentication, authenticators & identity ---
	"AEGIS-GCP-044": { // Cloud SQL instance without IAM database authentication
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-047": { // GKE cluster without workload identity
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-051": { // GKE cluster with basic authentication enabled
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-052": { // GKE cluster issuing client certificates
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-060": { // Compute instance without OS Login
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-065": { // Compute instance allows project-wide SSH keys
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-075": { // Service account with user-managed key
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-080": { // Workload identity pool without attribute restriction
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-089": { // Project metadata without OS Login enabled
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-108": { // GKE cluster without metadata server v2
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-123": { // Memorystore Redis without AUTH enabled
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-135": { // Cloud Scheduler HTTP target without authentication
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-143": { // Service account key expired or past validity
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-155": { // Cloud SQL user password stored in Terraform configuration
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-157": { // Cloud SQL instance without password validation policy
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-158": { // Cloud SQL root password stored in Terraform configuration
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-161": { // Cloud SQL with MD5 password encryption
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-164": { // GKE cluster nodes with legacy metadata endpoints enabled
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-171": { // GKE node pool with legacy metadata endpoints enabled
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-176": { // Compute instance without OS Login two-factor authentication
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-179": { // Instance template without OS Login
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-211": { // Backend service without Identity-Aware Proxy
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-290": { // Project metadata without enable-oslogin key
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-292": { // Project metadata item disabling OS Login
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-293": { // Secret in instance metadata startup script
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},

	// --- GCP expansion: hardening, integrity & platform currency ---
	"AEGIS-GCP-024": { // DNS managed zone without DNSSEC
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-043": { // Cloud SQL instance on outdated database version
		ref(nist, "SI-2"), ref(iso, "A.8.8"),
		ref(soc2, "CC7.1"),
	},
	"AEGIS-GCP-045": { // Cloud SQL instance with local_infile enabled
		ref(nist, "CM-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-GCP-049": { // GKE node pool with auto-upgrade disabled
		ref(nist, "SI-2"), ref(iso, "A.8.8"),
		ref(soc2, "CC7.1"),
	},
	"AEGIS-GCP-055": { // GKE cluster without shielded nodes
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-058": { // Compute instance with serial port access enabled
		ref(nist, "CM-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-GCP-059": { // Compute instance without secure boot
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-109": { // GKE cluster with binary authorization disabled
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-114": { // GKE cluster without a release channel
		ref(nist, "SI-2"), ref(iso, "A.8.8"),
		ref(soc2, "CC7.1"),
	},
	"AEGIS-GCP-117": { // GKE node pool without auto-upgrade
		ref(nist, "SI-2"), ref(iso, "A.8.8"),
		ref(soc2, "CC7.1"),
	},
	"AEGIS-GCP-174": { // Compute instance with vTPM disabled
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-175": { // Compute instance with integrity monitoring disabled
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-177": { // Instance template without secure boot
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-180": { // Instance template with serial port access enabled
		ref(nist, "CM-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-GCP-196": { // Cloud Run service image uses mutable tag
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-198": { // Cloud Run service without binary authorization
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-199": { // Cloud Run service on first-generation execution environment
		ref(nist, "SI-2"), ref(iso, "A.8.8"),
		ref(soc2, "CC7.1"),
	},
	"AEGIS-GCP-202": { // First-generation Cloud Function
		ref(nist, "SI-2"), ref(iso, "A.8.8"),
		ref(soc2, "CC7.1"),
	},
	"AEGIS-GCP-259": { // Artifact Registry Docker repository with mutable tags
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-261": { // Artifact Registry Maven repository allows snapshot overwrites
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-262": { // Artifact Registry Maven repository with snapshot version policy
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-271": { // Dataproc cluster without shielded instance config
		ref(nist, "SI-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-GCP-291": { // Project metadata item enabling serial port access
		ref(nist, "CM-7"), ref(iso, "A.8.9"),
		ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-GCP-294": { // Compute instance on end-of-life OS image
		ref(nist, "SI-2"), ref(iso, "A.8.8"),
		ref(soc2, "CC7.1"),
	},

	// --- GCP expansion: key & secret management ---
	"AEGIS-GCP-012": { // KMS crypto key without rotation
		ref(nist, "SC-12"), ref(pci, "3.6.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-022": { // Secret Manager secret without rotation
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-081": { // KMS crypto key with rotation period over 90 days
		ref(nist, "SC-12"), ref(pci, "3.6.1"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-084": { // KMS crypto key with weak algorithm
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-224": { // KMS crypto key with very short destroy-scheduled duration
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-225": { // KMS crypto key with software protection level
		ref(nist, "SC-12"), ref(iso, "A.8.24"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-GCP-230": { // Secret Manager rotation block without rotation period
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-GCP-231": { // Secret Manager secret with rotation period over 90 days
		ref(nist, "IA-5"), ref(iso, "A.5.17"),
		ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	// --- Platform: encryption at rest (SC-28) ---
	"AEGIS-ALI-001": { // OSS bucket without server-side encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-ALI-008": { // ECS disk without encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-ALI-010": { // RDS instance without transparent data encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-K8S-025": { // ConfigMap holds sensitive values (plaintext secret storage)
		ref(nist, "SC-28"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-OCI-001": { // Object Storage bucket without KMS encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-OCI-005": { // Block volume without KMS encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-OCI-006": { // Autonomous Database without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-TF-001": { // Terraform S3 backend without state encryption
		ref(nist, "SC-28"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},
	"AEGIS-TF-006": { // Terraform local backend stores state in plaintext
		ref(nist, "SC-28"), ref(iso, "A.8.24"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(2)(iv)"),
	},

	// --- Platform: public exposure & network boundary (AC-3 / SC-7 / SC-8) ---
	"AEGIS-ALI-002": { // OSS bucket publicly accessible
		ref(nist, "AC-3"), ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.1"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-ALI-009": { // ECS security group rule open to the world
		ref(nist, "SC-7"), ref(pci, "1.4.1"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-DOCKER-006": { // SSH port exposed in image
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-DOCKER-028": { // Privileged port exposed in image
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-K8S-020": { // Service exposed externally
		ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-K8S-021": { // Ingress without TLS
		ref(nist, "SC-8"), ref(pci, "4.2.1"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-K8S-031": { // Workload without a NetworkPolicy
		ref(cisk8s, "5.3.1"), ref(nist, "SC-7"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-OCI-002": { // Object Storage bucket with public access
		ref(nist, "AC-3"), ref(nist, "SC-7"), ref(pci, "1.4.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.1"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-OCI-003": { // VCN security list with open ingress
		ref(nist, "SC-7"), ref(pci, "1.4.1"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-SC-008": { // user_data downloads over plain HTTP
		ref(nist, "SC-8"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},
	"AEGIS-TF-005": { // Terraform backend using plaintext HTTP
		ref(nist, "SC-8"), ref(iso, "A.8.24"), ref(soc2, "CC6.7"), ref(hipaa, "164.312(e)(1)"),
	},

	// --- Platform: identity, privilege & secrets (AC-6 / IA-2 / IA-5) ---
	"AEGIS-ALI-005": { // RAM account password policy too weak
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-ALI-006": { // RAM login profile without MFA bind requirement
		ref(nist, "IA-2"), ref(iso, "A.5.17"), ref(iso, "A.8.5"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-ALI-007": { // RAM policy grants wildcard actions
		ref(nist, "AC-6"), ref(pci, "7.2.1"), ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-COMPOSE-004": { // Docker socket mounted into service (root-equivalent host access)
		ref(nist, "AC-6"), ref(nist, "CM-7"), ref(pci, "2.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(iso, "A.8.9"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-COMPOSE-005": { // Sensitive host path mounted into service
		ref(nist, "AC-3"), ref(nist, "CM-7"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(iso, "A.8.9"), ref(soc2, "CC6.1"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-COMPOSE-006": { // Secret in service environment
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-COMPOSE-007": { // Service runs as root
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-DOCKER-002": { // Container runs as root
		ref(cisdocker, "4.1"), ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-DOCKER-003": { // Secret in ENV directive
		ref(cisdocker, "4.10"), ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-DOCKER-011": { // Secret in ARG default value
		ref(cisdocker, "4.10"), ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-DOCKER-014": { // Overly permissive chmod in build (world-writable files baked into image)
		ref(nist, "AC-3"), ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-DOCKER-021": { // Sensitive file copied into image
		ref(cisdocker, "4.10"), ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-DOCKER-034": { // Credentials embedded in RUN layer
		ref(cisdocker, "4.10"), ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-DOCKER-037": { // Passwordless sudo configured (NOPASSWD)
		ref(nist, "AC-6"), ref(nist, "IA-5"), ref(pci, "7.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.5.17"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-K8S-002": { // Container running as root user
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-K8S-004": { // Pod securityContext explicitly allows root
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-K8S-010": { // Service account token automounted unnecessarily
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-K8S-019": { // Pod securityContext runs as UID 0
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-K8S-022": { // RBAC role with wildcard permissions
		ref(cisk8s, "5.1.3"), ref(nist, "AC-6"), ref(pci, "7.2.1"), ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-K8S-023": { // Binding grants cluster-admin
		ref(cisk8s, "5.1.1"), ref(nist, "AC-6"), ref(pci, "7.2.1"), ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-K8S-026": { // Secret in env variable
		ref(nist, "IA-5"), ref(iso, "A.5.17"), ref(soc2, "CC6.1"), ref(hipaa, "164.312(d)"),
	},
	"AEGIS-K8S-030": { // Container does not drop ALL capabilities (retained privileges)
		ref(nist, "AC-6"), ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-OCI-004": { // IAM policy with wildcard manage permissions
		ref(nist, "AC-6"), ref(pci, "7.2.1"), ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(hipaa, "164.312(a)(1)"),
	},

	// --- Platform: logging, audit & recovery (AU-2 / AU-9 / CP-9) ---
	"AEGIS-ALI-003": { // OSS bucket without versioning (no recovery from delete/overwrite)
		ref(nist, "CP-9"), ref(iso, "A.8.13"), ref(soc2, "CC7.4"), ref(hipaa, "164.310(d)(2)(iv)"),
	},
	"AEGIS-ALI-004": { // OSS bucket without access logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-ALI-011": { // ALB load balancer without access logging
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-ALI-012": { // ActionTrail trail without full event capture
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-OCI-007": { // Cloud Guard (security monitoring) not enabled
		ref(nist, "AU-2"), ref(iso, "A.8.15"), ref(soc2, "CC7.2"), ref(hipaa, "164.312(b)"),
	},
	"AEGIS-OCI-008": { // Logging log with short retention
		ref(nist, "AU-9"), ref(iso, "A.8.15"), ref(soc2, "CC7.3"), ref(hipaa, "164.312(b)"),
	},

	// --- Platform: container & workload hardening (CM-7) ---
	"AEGIS-COMPOSE-001": { // Service runs privileged
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-COMPOSE-002": { // Dangerous Linux capability granted
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-COMPOSE-003": { // Service shares host namespaces
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-COMPOSE-009": { // Service uses host network namespace (network_mode: host)
		ref(nist, "CM-7"), ref(nist, "SC-7"), ref(pci, "2.2.1"),
		ref(iso, "A.8.9"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-DOCKER-025": { // Build toolchain shipped in final image
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-DOCKER-026": { // Full OS base image (excess functionality / attack surface)
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-DOCKER-036": { // Build tools installed in final image
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-K8S-001": { // Container running as privileged
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-K8S-003": { // Container allows privilege escalation
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-K8S-005": { // Container with writable root filesystem
		ref(nist, "CM-7"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-K8S-007": { // Pod with hostNetwork enabled
		ref(nist, "CM-7"), ref(nist, "SC-7"), ref(pci, "2.2.1"),
		ref(iso, "A.8.9"), ref(iso, "A.8.20"), ref(iso, "A.8.22"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-K8S-008": { // Pod with hostPID enabled
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-K8S-009": { // Pod with hostIPC enabled
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-K8S-011": { // Pod with hostPath volume (host filesystem access)
		ref(nist, "AC-3"), ref(nist, "CM-7"), ref(pci, "2.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.3"), ref(iso, "A.8.9"), ref(soc2, "CC6.1"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-K8S-016": { // Container adds ALL Linux capabilities
		ref(nist, "AC-6"), ref(nist, "CM-7"), ref(pci, "2.2.1"),
		ref(iso, "A.5.15"), ref(iso, "A.8.2"), ref(iso, "A.8.9"), ref(soc2, "CC6.1"), ref(soc2, "CC6.3"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(a)(1)"),
	},
	"AEGIS-K8S-017": { // Seccomp profile set to Unconfined
		ref(nist, "CM-7"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-K8S-018": { // Pod shares process namespace
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-K8S-027": { // Workload defines no security context
		ref(nist, "CM-7"), ref(pci, "2.2.1"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-K8S-028": { // Container without read-only root filesystem
		ref(nist, "CM-7"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},
	"AEGIS-K8S-029": { // Container without seccomp profile
		ref(nist, "CM-7"), ref(iso, "A.8.9"), ref(soc2, "CC6.6"), ref(soc2, "CC7.1"),
	},

	// --- Platform: image & supply-chain integrity (SI-2 / SI-7) ---
	"AEGIS-COMPOSE-008": { // Service image uses :latest tag
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-DOCKER-001": { // Base image uses :latest tag
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-DOCKER-004": { // ADD used instead of COPY (implicit tar extraction / remote fetch semantics)
		ref(cisdocker, "4.9"), ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-DOCKER-005": { // No HEALTHCHECK directive (CIS-benchmarked; no NIST anchor in the spec set genuinely applies)
		ref(cisdocker, "4.6"),
	},
	"AEGIS-DOCKER-010": { // Base image from untrusted registry
		ref(cisdocker, "4.5"), ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-DOCKER-012": { // Remote script piped to shell
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-DOCKER-027": { // Base image uses floating major-only tag
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-DOCKER-035": { // ADD fetches remote URL (unverified remote content baked into image)
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-K8S-012": { // Container image uses latest tag
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-K8S-013": { // Container with imagePullPolicy Never (may silently run stale/tampered cached image)
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-K8S-032": { // Container image without digest pin
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-SC-001": { // Provider version affected by known advisory
		ref(nist, "SI-2"), ref(iso, "A.8.8"), ref(soc2, "CC7.1"),
	},
	"AEGIS-SC-002": { // Lambda function uses a public ECR image (untrusted artifact)
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-SC-003": { // user_data pipes a remote download into a shell
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-SC-004": { // EC2 instance uses an unpinned AMI
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-SC-005": { // Provisioner executes remote commands (arbitrary code execution at apply)
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-SC-006": { // null_resource executes local commands (supply-chain exfiltration/persistence vector)
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-SC-007": { // External data source executes an arbitrary program
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-SC-009": { // Lambda function uses a layer from an unrecognized account
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-TF-002": { // Terraform S3 backend without state locking (concurrent writes can corrupt state)
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
	"AEGIS-TF-003": { // Terraform provider without pinned version (executable plugin fetched at init)
		ref(nist, "SI-7"), ref(iso, "A.8.9"), ref(soc2, "CC7.1"), ref(hipaa, "164.312(c)(1)"),
	},
}
