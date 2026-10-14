package aws

import (
	"aegis/internal/ir"
)

// PackName identifies the AWS rule pack.
const PackName = "aegis-aws"

// Rules returns every rule in the AWS pack, in ID order.
func Rules() []ir.Rule {
	base := []ir.Rule{
		s3Encryption{},            // AEGIS-AWS-001
		s3PublicACL{},             // AEGIS-AWS-002
		s3PublicPolicy{},          // AEGIS-AWS-003
		sgOpenIngress{},           // AEGIS-AWS-004
		sgOpenEgress{},            // AEGIS-AWS-005
		iamAdminPolicy{},          // AEGIS-AWS-006
		rdsUnencrypted{},          // AEGIS-AWS-007
		rdsNoDeletionProtection{}, // AEGIS-AWS-008
		ebsUnencrypted{},          // AEGIS-AWS-009
		cloudtrailNoValidation{},  // AEGIS-AWS-010
		rdsPublic{},               // AEGIS-AWS-011
		s3Versioning{},            // AEGIS-AWS-012
		iamRoleOpenTrust{},        // AEGIS-AWS-101
		iamAdminManagedPolicy{},   // AEGIS-AWS-102
		rdsPublicPath{},           // AEGIS-AWS-103
		s3ExfiltrationPath{},      // AEGIS-AWS-104
		multiHopPath{},            // AEGIS-AWS-105
		lbInternetFacing{},        // AEGIS-AWS-201
		lbListenerPlainHTTP{},     // AEGIS-AWS-202
		lbNoHeaderDrop{},          // AEGIS-AWS-203
		ec2NoIMDSv2{},             // AEGIS-AWS-204
		subnetPublicIP{},          // AEGIS-AWS-205
		s3NoPublicAccessBlock{},   // AEGIS-AWS-206
		rdsNoBackup{},             // AEGIS-AWS-207
		elasticacheNoSnapshots{},  // AEGIS-AWS-208
		vpcNoFlowLogs{},           // AEGIS-AWS-209
	}
	// Service-area expansions (each in ID order within its block).
	base = append(base, ComputeRules()...)                // 301-310
	base = append(base, StorageRules()...)                // 311-322
	base = append(base, NetworkRules()...)                // 323-332
	base = append(base, IdentityRules()...)               // 333-340
	base = append(base, MessagingRules()...)              // 341-350
	base = append(base, Databases2Rules()...)             // 351-360
	base = append(base, AnalyticsRules()...)              // 361-370
	base = append(base, IntegrationRules()...)            // 371-380
	base = append(base, Compute2Rules()...)               // 381-390
	base = append(base, GovernanceRules()...)             // 391-400
	base = append(base, Edge2Rules()...)                  // 401-410
	base = append(base, Data2Rules()...)                  // 411-420
	base = append(base, Identity2Rules()...)              // 421-430
	base = append(base, FinalRules()...)                  // 431-442
	base = append(base, CheckovParityRules()...)          // 443-446
	base = append(base, IAMPrivilegeRules()...)           // 501-505
	base = append(base, NetworkExposureRules()...)        // 506-513
	base = append(base, EncryptionGapRules()...)          // 514-520
	base = append(base, AuthSupplyRules()...)             // 521-527
	base = append(base, HardeningRules()...)              // 528-533
	base = append(base, DeepSecretsRules()...)            // 534-539
	base = append(base, FinalGapRules()...)               // 540-544
	base = append(base, FinalGap2Rules()...)              // 545-551
	base = append(base, CoverageGapRules()...)            // 552-571
	base = append(base, HygieneRules()...)                // 601-626 (627/628 dupes of 209/445)
	base = append(base, killChain{}, iamPrivilegeChain{}) // AEGIS-AWS-629, AEGIS-AWS-630
	base = append(base, Databases3Rules()...)             // 631-636
	base = append(base, Search2Rules()...)                // 637-644
	base = append(base, Lambda2Rules()...)                // 645-649
	base = append(base, IAMDeepRules()...)                // 650-679
	base = append(base, ComputeDeepRules()...)            // 680-699
	base = append(base, DatabasesDeepRules()...)          // 700-719
	base = append(base, LambdaDeepRules()...)             // 720-739
	base = append(base, NetworkDeepRules()...)            // 740-759
	base = append(base, GovernanceDeepRules()...)         // 760-779
	base = append(base, KMSSecretsDeepRules()...)         // 780-799
	base = append(base, ServicesDeepRules()...)           // 800-824
	base = append(base, EdgeDeepRules()...)               // 825-849
	base = append(base, WeakPasswordRules()...)           // AEGIS-AWS-850
	base = append(base, CloudTrailCloudWatchRules()...)   // AEGIS-AWS-851
	base = append(base, CMKRefinementRules()...)          // AEGIS-AWS-852..855
	base = append(base, EOLImageRules()...)               // AEGIS-AWS-856
	return base
}
