// Package rules — compliance framework mappings.
//
// ComplianceFor maps rule IDs to the compliance-framework controls they
// violate. Mappings are maintained here (not on the rules themselves) so
// the rule pack stays focused on detection and frameworks can evolve
// independently. Only map where the control genuinely applies; when in
// doubt, leave the rule unmapped rather than stretching a control.
//
// Frameworks:
//   - CIS-AWS-1.5  — CIS Amazon Web Services Foundations Benchmark v1.5
//   - NIST-800-53  — NIST Special Publication 800-53 Rev. 5
//   - PCI-DSS-4.0  — PCI Data Security Standard v4.0
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
	cis  = "CIS-AWS-1.5"
	nist = "NIST-800-53"
	pci  = "PCI-DSS-4.0"
)

var complianceMap = map[string][]ir.ComplianceRef{
	// --- Criticals ---
	"AEGIS-AWS-003": { // S3 bucket policy allows public principal
		ref(cis, "2.1.1"), ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-006": { // IAM policy allows all actions on all resources
		ref(cis, "1.16"), ref(nist, "AC-6"), ref(pci, "7.2.1"),
	},
	"AEGIS-AWS-101": { // IAM role assumable by anyone
		ref(cis, "1.16"), ref(nist, "AC-3"), ref(pci, "7.2.1"),
	},
	"AEGIS-AWS-104": { // Public S3 exfiltration path
		ref(cis, "2.1.1"), ref(nist, "AC-4"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-202": { // Load balancer listener uses plain HTTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},

	// --- Highs: storage encryption ---
	"AEGIS-AWS-001": { // S3 bucket without server-side encryption
		ref(cis, "2.1.1"), ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-007": { // RDS instance without storage encryption
		ref(cis, "2.3.1"), ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-009": { // EBS volume without encryption
		ref(cis, "2.2.1"), ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-301": { // Launch template EBS volumes unencrypted
		ref(cis, "2.2.1"), ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-304": { // EKS cluster without secrets encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-307": { // Lambda function env vars without KMS
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-313": { // DynamoDB table without customer-managed encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-314": { // Redshift cluster unencrypted
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-317": { // EFS file system unencrypted
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-318": { // OpenSearch domain without node-to-node encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-319": { // OpenSearch domain without encryption at rest
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-341": { // SNS topic without KMS encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-342": { // SQS queue without encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-345": { // MSK cluster without encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-350": { // Kinesis stream without encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-351": { // DocumentDB cluster unencrypted
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-352": { // Neptune cluster unencrypted
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-359": { // Aurora cluster unencrypted
		ref(cis, "2.3.1"), ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-361": { // EMR security configuration without at-rest encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-363": { // Athena workgroup without result encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-364": { // Glue data catalog without SSE-KMS encryption
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-366": { // SageMaker notebook instance without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-368": { // FSx Windows file system without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-369": { // FSx Lustre file system without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-411": { // EC2 instance EBS volumes unencrypted
		ref(cis, "2.2.1"), ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-416": { // FSx OpenZFS file system without customer-managed KMS key
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},
	"AEGIS-AWS-424": { // WorkSpaces volumes unencrypted
		ref(nist, "SC-28"), ref(pci, "3.5.1"),
	},

	// --- Highs: public exposure / access control ---
	"AEGIS-AWS-002": { // S3 bucket with public ACL
		ref(cis, "2.1.1"), ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-004": { // Security group ingress open to the world
		ref(cis, "5.2"), ref(nist, "SC-7"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-011": { // RDS instance publicly accessible
		ref(cis, "2.3.3"), ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-102": { // IAM managed policy grants administrative access
		ref(cis, "1.16"), ref(nist, "AC-6"), ref(pci, "7.2.1"),
	},
	"AEGIS-AWS-103": { // Public RDS exposure path
		ref(cis, "2.3.3"), ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-201": { // Load balancer internet-facing
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-205": { // Subnet auto-assigns public IPs
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-206": { // S3 bucket without public access block
		ref(cis, "2.1.5"), ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-305": { // EKS cluster with public endpoint
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-315": { // Redshift cluster publicly accessible
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-333": { // Inline admin policy attached to role/user/group
		ref(cis, "1.16"), ref(nist, "AC-6"), ref(pci, "7.2.1"),
	},
	"AEGIS-AWS-343": { // SNS topic policy allows public principal
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-344": { // SQS queue policy allows public principal
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-356": { // DMS replication instance publicly accessible
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-372": { // API Gateway v2 CORS allows all origins
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-375": { // EventBridge permission open to all principals
		ref(nist, "AC-3"),
	},
	"AEGIS-AWS-378": { // WAFv2 Web ACL allows all traffic with no rules
		ref(nist, "SC-7"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-381": { // ECS service with public IP assignment
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-390": { // IoT policy with overly broad Allow statement
		ref(nist, "AC-6"), ref(pci, "7.2.1"),
	},
	"AEGIS-AWS-399": { // RAM resource share allows external principals
		ref(nist, "AC-3"),
	},
	"AEGIS-AWS-403": { // API Gateway method without authorization
		ref(nist, "IA-2"),
	},
	"AEGIS-AWS-404": { // API Gateway v2 route without authorization
		ref(nist, "IA-2"),
	},
	"AEGIS-AWS-406": { // Lambda permission grants invoke to everyone
		ref(nist, "AC-3"), ref(pci, "7.2.1"),
	},
	"AEGIS-AWS-407": { // Lambda function URL without authorization
		ref(nist, "IA-2"),
	},
	"AEGIS-AWS-408": { // ECR repository policy allows public principal
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-414": { // S3 account public access block disabled
		ref(cis, "2.1.5"), ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-415": { // EFS file system policy allows public principal
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-420": { // KMS key policy allows public principal
		ref(nist, "AC-3"),
	},
	"AEGIS-AWS-421": { // Cognito identity pool allows unauthenticated identities
		ref(nist, "IA-2"),
	},
	"AEGIS-AWS-422": { // SSO permission set with inline admin policy
		ref(cis, "1.16"), ref(nist, "AC-6"), ref(pci, "7.2.1"),
	},
	"AEGIS-AWS-428": { // ElastiCache user with open access string
		ref(nist, "AC-3"),
	},
	"AEGIS-AWS-431": { // Redshift Serverless workgroup publicly accessible
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-433": { // VPC endpoint with public policy
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-441": { // S3 access point policy allows public principal
		ref(cis, "2.1.1"), ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},
	"AEGIS-AWS-444": { // EC2 instance with public IP address
		ref(nist, "AC-3"), ref(pci, "1.4.1"),
	},

	// --- Highs: encryption in transit ---
	"AEGIS-AWS-324": { // Load balancer listener with weak TLS policy
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-325": { // CloudFront distribution allows HTTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-326": { // API Gateway custom domain with weak TLS
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-329": { // Load balancer target group uses plain HTTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-354": { // MemoryDB cluster without TLS
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-357": { // DMS endpoint without SSL
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-379": { // Transfer server allows plaintext FTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-401": { // Classic ELB with plain-HTTP listener
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-405": { // CloudFront custom origin fetched over plain HTTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-426": { // SNS subscription over plaintext HTTP
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-436": { // RDS proxy without TLS enforcement
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-443": { // S3 bucket policy does not enforce TLS (SecureTransport)
		ref(cis, "2.1.2"), ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},

	// --- Highs: keys, secrets, identity ---
	"AEGIS-AWS-335": { // KMS key without rotation
		ref(cis, "3.8"), ref(nist, "SC-12"), ref(pci, "3.6.1"),
	},
	"AEGIS-AWS-338": { // SSM parameter stores plaintext secret
		ref(nist, "SC-28"),
	},
	"AEGIS-AWS-339": { // Hardcoded credentials in resource config
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-410": { // API Gateway API key hardcoded in config
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-425": { // Secrets Manager version with hardcoded secret
		ref(nist, "IA-5"),
	},

	// --- Highs: hardening ---
	"AEGIS-AWS-203": { // Load balancer not dropping invalid headers
		ref(nist, "SC-7"),
	},
	"AEGIS-AWS-204": { // EC2 instance without IMDSv2 enforcement
		ref(nist, "AC-3"),
	},
	"AEGIS-AWS-302": { // ECS task definition with privileged container
		ref(nist, "CM-7"), ref(pci, "2.2.1"),
	},
	"AEGIS-AWS-385": { // CodeBuild project with privileged mode
		ref(nist, "CM-7"), ref(pci, "2.2.1"),
	},
	"AEGIS-AWS-412": { // ECS task definition with host networking
		ref(nist, "CM-7"), ref(pci, "2.2.1"),
	},

	// --- Highs: logging / audit ---
	"AEGIS-AWS-010": { // CloudTrail without log file validation
		ref(cis, "3.2"), ref(nist, "AU-9"), ref(pci, "10.3.1"),
	},
	"AEGIS-AWS-336": { // CloudTrail not multi-region
		ref(cis, "3.1"), ref(nist, "AU-2"), ref(pci, "10.3.1"),
	},
}
