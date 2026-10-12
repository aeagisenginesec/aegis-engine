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

	// --- GCP criticals/highs (NIST-800-53 only; CIS/PCI maps are AWS-specific) ---
	"AEGIS-GCP-145": { // SA key with weak RSA-1024
		ref(nist, "IA-2"), ref(nist, "SC-12"),
	},
	"AEGIS-GCP-146": { // SA impersonation broad grant
		ref(nist, "AC-6"),
	},
	"AEGIS-GCP-148": { // Org IAM basic roles
		ref(nist, "AC-3"), ref(nist, "AC-6"),
	},
	"AEGIS-GCP-149": { // Folder IAM basic roles
		ref(nist, "AC-3"), ref(nist, "AC-6"),
	},
	"AEGIS-GCP-152": { // Project IAM Admin grant
		ref(nist, "AC-6"),
	},
	"AEGIS-GCP-162": { // Cloud SQL SSL permissive
		ref(nist, "SC-8"), ref(nist, "SC-12"),
	},
	"AEGIS-GCP-167": { // GKE alpha cluster
		ref(nist, "CM-7"),
	},
	"AEGIS-GCP-170": { // GKE master open to world
		ref(nist, "AC-3"), ref(nist, "SC-7"),
	},
	"AEGIS-GCP-178": { // Instance template public IP
		ref(nist, "SC-7"),
	},
	"AEGIS-GCP-185": { // GCS bucket IAM public
		ref(nist, "AC-3"),
	},
	"AEGIS-GCP-186": { // GCS default object ACL public
		ref(nist, "AC-3"),
	},
	"AEGIS-GCP-188": { // GCS bucket IAM admin to domain
		ref(nist, "AC-3"), ref(nist, "AC-6"),
	},
	"AEGIS-GCP-190": { // GCS bucket publicly writable
		ref(nist, "AC-3"),
	},
	"AEGIS-GCP-191": { // BigQuery dataset bigquery.admin
		ref(nist, "AC-6"),
	},
	"AEGIS-GCP-192": { // BigQuery table IAM public
		ref(nist, "AC-3"),
	},
	"AEGIS-GCP-194": { // BigQuery dataset dataOwner
		ref(nist, "AC-6"),
	},
	"AEGIS-GCP-200": { // Cloud Function EOL runtime
		ref(nist, "SI-7"), ref(nist, "CM-7"),
	},
	"AEGIS-GCP-205": { // Pub/Sub subscription IAM public
		ref(nist, "AC-3"),
	},
	"AEGIS-GCP-214": { // Firewall all ports to world
		ref(nist, "SC-7"),
	},
	"AEGIS-GCP-219": { // SSL weak ciphers
		ref(nist, "SC-12"),
	},
	"AEGIS-GCP-226": { // Secret Manager IAM public
		ref(nist, "AC-3"),
	},
	"AEGIS-GCP-227": { // Secret value in TF state
		ref(nist, "SC-28"),
	},
	"AEGIS-GCP-245": { // Redis AUTH string in state
		ref(nist, "SC-28"),
	},
	"AEGIS-GCP-257": { // Artifact Registry over HTTP
		ref(nist, "SC-8"),
	},
	"AEGIS-GCP-260": { // Artifact Registry IAM public
		ref(nist, "AC-3"),
	},

	// --- AWS deep expansion (650-849) ---
	"AEGIS-AWS-650": { // IAM password policy minimum length below 14
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-651": { // IAM password policy does not require uppercase characters
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-652": { // IAM password policy does not require lowercase characters
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-653": { // IAM password policy does not require numbers
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-654": { // IAM password policy does not require symbols
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-655": { // IAM password policy allows password reuse
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-656": { // IAM password maximum age too long or disabled
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-660": { // IAM policy grants sensitive service wildcard on all resources
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-661": { // IAM policy grants iam:PassRole on all resources
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-663": { // IAM password policy has no maximum password age
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-664": { // IAM user has force_destroy enabled
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-665": { // IAM role allows forced policy detach on destroy
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-666": { // IAM policy attachment grants AdministratorAccess
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-667": { // IAM role has no permissions boundary
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-668": { // IAM access key secret not encrypted with pgp_key
		ref(nist, "IA-5"), ref(nist, "SC-12"),
	},
	"AEGIS-AWS-669": { // IAM role policy attachment grants PowerUserAccess
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-670": { // IAM policy grants iam:* on a scoped resource
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-671": { // IAM policy Allow statement uses NotResource
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-674": { // IAM group named admin should be reviewed
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-675": { // IAM password policy allows reset after expiry
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-676": { // IAM role trust grants sts:TagSession without conditions
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-677": { // IAM policy statement has no Sid
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-678": { // IAM login profile does not force password reset
		ref(cis, "1.8"), ref(nist, "AU-2"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-679": { // Production-like IAM role attached to ReadOnlyAccess
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-685": { // EC2 instance with Windows password retrieval enabled
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-686": { // EC2 user_data embeds AWS credentials
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-687": { // Launch template user_data embeds a hardcoded password
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-688": { // Network interface with public IP association
		ref(nist, "SC-7"),
	},
	"AEGIS-AWS-692": { // EC2 instance without an IAM instance profile
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-694": { // AMI copy without encryption
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-695": { // EBS snapshot copy without encryption
		ref(nist, "CP-9"), ref(nist, "SC-12"),
	},
	"AEGIS-AWS-696": { // EC2 root volume without encryption
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-700": { // Aurora Performance Insights without customer-managed KMS key
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-701": { // RDS instance without enhanced monitoring
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-702": { // RDS instance snapshots do not copy tags
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-703": { // Aurora cluster skips final snapshot on deletion
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-704": { // Aurora cluster without automated backups
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-705": { // Aurora cluster snapshot shared with other accounts
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-709": { // RDS parameter group without forced SSL
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-710": { // RDS master password not managed by Secrets Manager
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-712": { // Redshift cluster with short snapshot retention
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-713": { // Redshift cluster snapshots do not copy tags
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-714": { // ElastiCache cluster without snapshot retention
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-715": { // ElastiCache replication group without at-rest encryption
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-717": { // ElastiCache replication group without snapshot retention
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-719": { // Neptune cluster without deletion protection
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-720": { // Lambda async invoke config without a failure destination
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-724": { // Lambda permission grants a service principal without source_arn
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-725": { // Lambda code signing policy warns instead of enforcing
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-729": { // Step Functions state machine with logging switched off
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-731": { // Step Functions definition contains a hardcoded password
		ref(cis, "1.8"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-733": { // Lambda code signing config without allowed publishers
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-735": { // ECS container without log configuration
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-738": { // EKS cluster control plane logging without audit logs
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-739": { // EKS encryption config not covering Kubernetes secrets
		ref(nist, "AU-2"), ref(nist, "IA-5"), ref(nist, "SC-12"),
	},
	"AEGIS-AWS-741": { // Load balancer listener with TLS protocol on port 80
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-744": { // Route sending all traffic to an internet gateway
		ref(nist, "SC-7"),
	},
	"AEGIS-AWS-745": { // Default security group with a world-open rule
		ref(nist, "SC-7"),
	},
	"AEGIS-AWS-750": { // ACM certificate using email validation
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-751": { // API Gateway REST API with a public resource policy
		ref(nist, "IA-5"), ref(nist, "SC-7"),
	},
	"AEGIS-AWS-752": { // CloudFront distribution without access logging
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-754": { // CloudFront viewer certificate with TLS 1.0 minimum
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-756": { // API Gateway stage without a client certificate
		ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-759": { // Network Firewall without firewall policy change protection
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-760": { // CloudTrail trail is not an organization trail
		ref(cis, "3.1"), ref(nist, "AU-2"),
	},
	"AEGIS-AWS-761": { // CloudTrail trail without CloudTrail Insights
		ref(cis, "3.1"), ref(nist, "AU-2"),
	},
	"AEGIS-AWS-762": { // CloudTrail trail logging disabled
		ref(cis, "3.1"), ref(nist, "AU-2"),
	},
	"AEGIS-AWS-763": { // Config recorder skips global resource types
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-764": { // Config delivery channel without S3 key prefix
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-765": { // Config recorder status disabled
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-766": { // GuardDuty finding publishing disabled
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-767": { // GuardDuty S3 protection disabled
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-769": { // CloudWatch log group with short log retention
		ref(nist, "AU-2"), ref(nist, "CP-9"),
	},
	"AEGIS-AWS-770": { // CloudWatch log group using AWS-managed encryption key
		ref(nist, "AU-2"), ref(nist, "SC-12"),
	},
	"AEGIS-AWS-771": { // CloudWatch alarm with no alarm actions
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-772": { // SNS topic using AWS-managed encryption key
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-774": { // SNS topic policy grants wildcard actions
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-775": { // SQS queue using AWS-managed encryption key
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-777": { // SQS queue with short message retention
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-778": { // SQS queue policy grants wildcard actions
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-780": { // KMS key rotation period longer than one year
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-781": { // KMS key with short deletion window
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-782": { // KMS key policy allows public principal
		ref(nist, "IA-5"), ref(nist, "SC-12"), ref(nist, "SC-7"),
	},
	"AEGIS-AWS-783": { // KMS key without description
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-784": { // KMS external key without key material expiry
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-785": { // KMS key bypasses policy lockout safety check
		ref(nist, "IA-5"), ref(nist, "SC-12"),
	},
	"AEGIS-AWS-786": { // EBS default encryption uses AWS-managed key
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-787": { // Secrets Manager secret using AWS-managed encryption key
		ref(nist, "IA-5"), ref(nist, "SC-12"),
	},
	"AEGIS-AWS-788": { // Secrets Manager rotation interval above 30 days
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-789": { // Secrets Manager secret without description
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-790": { // SSM SecureString parameter using default KMS key
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-791": { // SSM StringList parameter stores plaintext secret
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-792": { // SSM document shared publicly
		ref(nist, "SC-7"),
	},
	"AEGIS-AWS-793": { // Secrets Manager secret version with weak placeholder secret
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-794": { // KMS grant with decrypt and retire-grant operations
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-795": { // KMS grant to public grantee principal
		ref(nist, "IA-5"), ref(nist, "SC-12"), ref(nist, "SC-7"),
	},
	"AEGIS-AWS-796": { // Secrets Manager secret policy allows public principal
		ref(nist, "IA-5"), ref(nist, "SC-7"),
	},
	"AEGIS-AWS-798": { // KMS key policy statement without Sid
		ref(nist, "IA-5"), ref(nist, "SC-12"),
	},
	"AEGIS-AWS-799": { // Secrets Manager secret with zero recovery window
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-800": { // Bedrock invocation logging without text data delivery
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-801": { // Bedrock guardrail without a content policy
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-802": { // SageMaker notebook instance with direct internet access
		ref(nist, "SC-7"),
	},
	"AEGIS-AWS-805": { // SageMaker domain allowing public internet app access
		ref(nist, "SC-7"),
	},
	"AEGIS-AWS-806": { // EventBridge archive with zero-day retention
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-807": { // EventBridge Scheduler schedule without a KMS key
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-809": { // MSK cluster without per-topic enhanced monitoring
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-811": { // OpenSearch domain without advanced security options
		ref(nist, "SC-7"),
	},
	"AEGIS-AWS-812": { // OpenSearch domain without log publishing options
		ref(nist, "AU-2"), ref(nist, "SC-7"),
	},
	"AEGIS-AWS-813": { // Neptune cluster skipping the final snapshot
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-814": { // Neptune cluster not copying tags to snapshots
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-815": { // DocumentDB cluster without deletion protection
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-816": { // App Runner service without encryption configuration
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-819": { // Glue security configuration without encryption configuration
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-820": { // Athena workgroup without SSE-KMS query result encryption
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-822": { // Kinesis stream without shard-level metrics
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-823": { // Firehose delivery stream without server-side encryption
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-824": { // Timestream scheduled query error reports without SSE-KMS
		ref(nist, "SC-12"),
	},
	"AEGIS-AWS-826": { // CloudFront distribution without a response headers policy
		ref(nist, "IA-5"),
	},
	"AEGIS-AWS-830": { // API Gateway v2 stage without access logging
		ref(nist, "AU-2"),
	},
	"AEGIS-AWS-832": { // API Gateway v2 domain name with TLS 1.0 security policy
		ref(nist, "IA-5"), ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-834": { // Backup vault lock with short minimum retention
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-835": { // Backup plan rule without a copy action
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-836": { // Backup vault without vault lock configuration
		ref(nist, "CP-9"),
	},
	"AEGIS-AWS-839": { // ACM certificate with certificate transparency logging disabled
		ref(nist, "AU-2"), ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-842": { // ALB listener with an outdated SSL policy
		ref(nist, "IA-5"), ref(nist, "SC-8"), ref(pci, "4.2.1"),
	},
	"AEGIS-AWS-843": { // API Gateway account without a CloudWatch logging role
		ref(nist, "AU-2"), ref(nist, "IA-5"),
	},
	"AEGIS-AWS-847": { // DLM lifecycle policy disabled
		ref(nist, "IA-5"),
	},
}
