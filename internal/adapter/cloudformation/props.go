package cloudformation

import (
	"strings"

	"gopkg.in/yaml.v3"

	"aegis/internal/ir"
)

// specialConverters handles resource types whose CloudFormation property
// structure differs enough from Terraform's that generic snake_case
// conversion would miss rule-relevant attributes. Each converter receives
// the generically-converted attributes and may reshape them and/or append
// companion resources (returned second).
type specialConverter func(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource)

var specialConverters = map[string]specialConverter{
	"AWS::S3::Bucket":                    convertS3Bucket,
	"AWS::S3::BucketPolicy":              convertS3BucketPolicy,
	"AWS::IAM::Role":                     convertIAMRole,
	"AWS::IAM::Policy":                   convertIAMPolicy,
	"AWS::IAM::ManagedPolicy":            convertIAMManagedPolicy,
	"AWS::IAM::User":                     convertIAMUser,
	"AWS::KMS::Key":                      convertKMSKey,
	"AWS::EC2::SecurityGroup":            convertSecurityGroup,
	"AWS::RDS::DBInstance":               convertDBInstance,
	"AWS::CloudTrail::Trail":             convertCloudTrail,
	"AWS::DynamoDB::Table":               convertDynamoDBTable,
	"AWS::ElastiCache::ReplicationGroup": convertElastiCacheRG,
	"AWS::Redshift::Cluster":             convertRedshiftCluster,
	"AWS::OpenSearchService::Domain":     convertOpenSearch,
	"AWS::Elasticsearch::Domain":         convertOpenSearch,
}

// propertyRenames maps CloudFormation property names (PascalCase) to the
// Terraform attribute names the rule pack expects, for cases where generic
// snake_case conversion produces the wrong name. Keyed by CFN resource type;
// a "*" key applies to all types.
var propertyRenames = map[string]map[string]string{
	"*": {
		// Common cross-type renames
	},
	"AWS::S3::Bucket": {
		"AccessControl": "acl",
		"BucketName":    "bucket",
	},
	"AWS::RDS::DBInstance": {
		"DBInstanceIdentifier": "identifier",
		"DBInstanceClass":      "instance_class",
		"MasterUsername":       "username",
		"MasterUserPassword":   "password",
		"AllocatedStorage":     "allocated_storage",
		"Engine":               "engine",
		"PubliclyAccessible":   "publicly_accessible",
		"SkipFinalSnapshot":    "skip_final_snapshot",
		"StorageEncrypted":     "storage_encrypted",
	},
	"AWS::IAM::ManagedPolicy": {
		"PolicyDocument":    "policy",
		"ManagedPolicyName": "name",
		"Description":       "description",
	},
	"AWS::IAM::Policy": {
		"PolicyDocument": "policy",
		"PolicyName":     "name",
	},
	"AWS::Lambda::Url": {
		"AuthType": "authorization_type",
	},
	"AWS::EC2::SecurityGroup": {
		"GroupName":        "name",
		"GroupDescription": "description",
		"VpcId":            "vpc_id",
	},
}

// renameProperty returns the TF attribute name for a CFN property,
// consulting the rename table before falling back to snakeCase.
func renameProperty(cfnType, cfnProp string) string {
	if m, ok := propertyRenames[cfnType]; ok {
		if tf, ok := m[cfnProp]; ok {
			return tf
		}
	}
	if m, ok := propertyRenames["*"]; ok {
		if tf, ok := m[cfnProp]; ok {
			return tf
		}
	}
	return snakeCase(cfnProp)
}

// convertProperties converts a CFN Properties mapping to TF-style
// attributes: generic recursive snake_case conversion, then the
// type-specific special converter if one exists.
func (t *template) convertProperties(cfnType, tfType string, props *yaml.Node) map[string]ir.Value {
	attrs := map[string]ir.Value{}
	if props == nil || props.Kind != yaml.MappingNode {
		return attrs
	}
	for i := 0; i+1 < len(props.Content); i += 2 {
		k := props.Content[i]
		if k.Kind != yaml.ScalarNode {
			continue
		}
		name := renameProperty(cfnType, k.Value)
		v := t.resolveValue(props.Content[i+1])
		// Preserve a useful span: point at the property key.
		if v.Known {
			v.Span = nodeSpan(t.path, k)
		}
		attrs[name] = v
	}
	return attrs
}

// --- special converters ---

// cfnACLToTF maps CloudFormation AccessControl enum values to the
// Terraform acl values the S3 rules expect.
var cfnACLToTF = map[string]string{
	"Private":               "private",
	"PublicRead":            "public-read",
	"PublicReadWrite":       "public-read-write",
	"AuthenticatedRead":     "authenticated-read",
	"LogDeliveryWrite":      "log-delivery-write",
	"BucketOwnerRead":       "bucket-owner-read",
	"BucketOwnerFullControl": "bucket-owner-full-control",
	"AwsExecRead":           "aws-exec-read",
}

// convertS3Bucket reshapes BucketEncryption, VersioningConfiguration and
// LoggingConfiguration into the Terraform shapes rules expect, and
// synthesizes an aws_s3_bucket_public_access_block companion when the
// template configures public access blocks inline.
func convertS3Bucket(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	props := mappingGet(def, "Properties")
	var companions []ir.Resource
	if props == nil {
		return attrs, nil
	}

	// AccessControl enum -> TF acl value (PublicRead -> public-read).
	if v, ok := attrs["acl"]; ok && v.Known {
		if s, ok := v.AsString(); ok {
			if tf, ok := cfnACLToTF[s]; ok {
				v.Raw = tf
				attrs["acl"] = v
			}
		}
	}

	// BucketEncryption -> server_side_encryption_configuration (TF shape).
	if be := mappingGet(props, "BucketEncryption"); be != nil {
		if ssec := mappingGet(be, "ServerSideEncryptionConfiguration"); ssec != nil {
			attrs["server_side_encryption_configuration"] = t.s3EncryptionBlock(ssec, be)
		}
		delete(attrs, "bucket_encryption")
	}

	// VersioningConfiguration: {Status: Enabled} -> versioning [{enabled: true}].
	if vc := mappingGet(props, "VersioningConfiguration"); vc != nil {
		if st := mappingGet(vc, "Status"); st != nil {
			if s, ok := t.resolveString(st); ok {
				attrs["versioning"] = blockList(t.path, vc, map[string]ir.Value{
					"enabled": {Raw: s == "Enabled", Known: true, Span: nodeSpan(t.path, st)},
				})
			}
		}
		delete(attrs, "versioning_configuration")
	}

	// LoggingConfiguration -> companion aws_s3_bucket_logging resource
	// (the shape the S3 logging rules expect), plus inline logging attr.
	if lc := mappingGet(props, "LoggingConfiguration"); lc != nil {
		m := map[string]ir.Value{}
		if d := mappingGet(lc, "DestinationBucketName"); d != nil {
			tv := t.resolveValue(d)
			// If it's a Ref to a known resource logical ID, use the ID
			// string so linkedTargetBucketAddr can match by resource Name.
			if tv.IsRef() && strings.HasPrefix(tv.Ref, "cfn.resource.") {
				lid := strings.TrimPrefix(tv.Ref, "cfn.resource.")
				tv = ir.Value{Raw: lid, Known: true, Span: tv.Span}
			}
			m["target_bucket"] = tv
		}
		if p := mappingGet(lc, "LogFilePrefix"); p != nil {
			m["target_prefix"] = t.resolveValue(p)
		}
		attrs["logging"] = blockList(t.path, lc, m)
		delete(attrs, "logging_configuration")
		// Synthesize companion so cross-resource rules (logDeliveryBuckets,
		// s3NoAccessLogging) recognize the logging link.
		cattrs := map[string]ir.Value{
			"bucket": {Raw: logicalID, Known: true, Span: nodeSpan(t.path, lc)},
		}
		for k, v := range m {
			cattrs[k] = v
		}
		companions = append(companions, ir.Resource{
			Type:       "aws_s3_bucket_logging",
			Name:       logicalID + "-logging",
			Provider:   "aws",
			Attributes: cattrs,
			Span:       nodeSpan(t.path, lc),
		})
	}

	// PublicAccessBlockConfiguration -> companion aws_s3_bucket_public_access_block.
	if pab := mappingGet(props, "PublicAccessBlockConfiguration"); pab != nil && pab.Kind == yaml.MappingNode {		cattrs := map[string]ir.Value{
			"bucket": {Raw: logicalID, Known: true, Span: nodeSpan(t.path, pab)},
		}
		for _, k := range []string{"BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"} {
			if n := mappingGet(pab, k); n != nil {
				cattrs[snakeCase(k)] = t.resolveValue(n)
			}
		}
		companions = append(companions, ir.Resource{
			Type:       "aws_s3_bucket_public_access_block",
			Name:       logicalID + "-pab",
			Provider:   "aws",
			Attributes: cattrs,
			Span:       nodeSpan(t.path, pab),
		})
		delete(attrs, "public_access_block_configuration")
	}

	// WebsiteConfiguration -> website [{index_document}].
	if wc := mappingGet(props, "WebsiteConfiguration"); wc != nil {
		m := map[string]ir.Value{}
		if idx := mappingGet(wc, "IndexDocument"); idx != nil {
			m["index_document"] = t.resolveValue(idx)
		}
		if err := mappingGet(wc, "ErrorDocument"); err != nil {
			m["error_document"] = t.resolveValue(err)
		}
		attrs["website"] = blockList(t.path, wc, m)
		delete(attrs, "website_configuration")
	}
	return attrs, companions
}

// s3EncryptionBlock builds the TF server_side_encryption_configuration
// shape from CFN ServerSideEncryptionConfiguration.
func (t *template) s3EncryptionBlock(ssec, parent *yaml.Node) ir.Value {
	span := nodeSpan(t.path, parent)
	var rules []ir.Value
	if ssec.Kind == yaml.SequenceNode {
		for _, item := range ssec.Content {
			byDefault := mappingGet(item, "ServerSideEncryptionByDefault")
			if byDefault == nil {
				continue
			}
			def := map[string]ir.Value{}
			if a := mappingGet(byDefault, "SSEAlgorithm"); a != nil {
				def["sse_algorithm"] = t.resolveValue(a)
			}
			if k := mappingGet(byDefault, "KMSMasterKeyID"); k != nil {
				def["kms_master_key_id"] = t.resolveValue(k)
			}
			rules = append(rules, ir.Value{
				Raw: map[string]ir.Value{
					"apply_server_side_encryption_by_default": blockListVal(t.path, byDefault, def),
				},
				Known: true, Span: nodeSpan(t.path, item),
			})
		}
	}
	return ir.Value{
		Raw:   []ir.Value{{Raw: map[string]ir.Value{"rule": {Raw: rules, Known: true, Span: span}}, Known: true, Span: span}},
		Known: true, Span: span,
	}
}

// blockList wraps one block map as a TF-style block list value.
func blockList(path string, n *yaml.Node, m map[string]ir.Value) ir.Value {
	return ir.Value{Raw: []ir.Value{{Raw: m, Known: true, Span: nodeSpan(path, n)}}, Known: true, Span: nodeSpan(path, n)}
}

func blockListVal(path string, n *yaml.Node, m map[string]ir.Value) ir.Value {
	return blockList(path, n, m)
}

// convertS3BucketPolicy maps BucketPolicy -> aws_s3_bucket_policy with a
// JSON-encoded policy string.
func convertS3BucketPolicy(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	props := mappingGet(def, "Properties")
	if props == nil {
		return attrs, nil
	}
	if b := mappingGet(props, "Bucket"); b != nil {
		attrs["bucket"] = t.resolveValue(b)
	}
	if pd := mappingGet(props, "PolicyDocument"); pd != nil {
		// Preserve IAM policy key casing (Statement, Principal, ...):
		// the rules parse the document case-sensitively for these keys,
		// and snake_casing them silently breaks public-principal
		// detection (the same bug class as IAM PolicyDocument handling).
		attrs["policy"] = jsonStringPreserveCase(t.path, pd, t)
		delete(attrs, "policy_document")
	}
	return attrs, nil
}

// convertIAMRole maps AssumeRolePolicyDocument (map) -> assume_role_policy
// (JSON string) and synthesizes aws_iam_role_policy companions for inline
// Policies.
func convertIAMRole(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	props := mappingGet(def, "Properties")
	var companions []ir.Resource
	if props == nil {
		return attrs, nil
	}
	if d := mappingGet(props, "AssumeRolePolicyDocument"); d != nil {
		attrs["assume_role_policy"] = jsonStringPreserveCase(t.path, d, t)
		delete(attrs, "assume_role_policy_document")
	}
	if pa := mappingGet(props, "ManagedPolicyArns"); pa != nil {
		attrs["managed_policy_arns"] = t.resolveValue(pa)
		delete(attrs, "managed_policy_arns")
	}
	if pols := mappingGet(props, "Policies"); pols != nil && pols.Kind == yaml.SequenceNode {
		for _, p := range pols.Content {
			pn := mappingGet(p, "PolicyName")
			pd := mappingGet(p, "PolicyDocument")
			if pn == nil || pd == nil {
				continue
			}
			name, ok := t.resolveString(pn)
			if !ok {
				name = logicalID + "-inline"
			}
			companions = append(companions, ir.Resource{
				Type:     "aws_iam_role_policy",
				Name:     logicalID + "-" + name,
				Provider: "aws",
				Attributes: map[string]ir.Value{
					"name":   {Raw: name, Known: true, Span: nodeSpan(t.path, pn)},
					"role":   {Raw: logicalID, Known: true, Span: nodeSpan(t.path, p)},
					"policy": jsonString(t.path, pd, t),
				},
				Span: nodeSpan(t.path, p),
			})
		}
		delete(attrs, "policies")
	}
	return attrs, companions
}

// convertIAMPolicy maps PolicyDocument -> policy (JSON string).
func convertIAMPolicy(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	props := mappingGet(def, "Properties")
	if props == nil {
		return attrs, nil
	}
	if pd := mappingGet(props, "PolicyDocument"); pd != nil {
		// Preserve IAM policy key casing (Statement, Action, etc.)
		attrs["policy"] = jsonStringPreserveCase(t.path, pd, t)
		delete(attrs, "policy_document")
	}
	for _, k := range []string{"Roles", "Users", "Groups"} {
		if n := mappingGet(props, k); n != nil {
			attrs[snakeCase(k)] = t.resolveValue(n)
		}
	}
	if n := mappingGet(props, "PolicyName"); n != nil {
		attrs["name"] = t.resolveValue(n)
		delete(attrs, "policy_name")
	}
	return attrs, nil
}

// convertIAMManagedPolicy is identical in shape to convertIAMPolicy.
func convertIAMManagedPolicy(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	return convertIAMPolicy(t, logicalID, tfType, attrs, def)
}

// convertIAMUser handles inline Policies like convertIAMRole.
func convertIAMUser(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	props := mappingGet(def, "Properties")
	var companions []ir.Resource
	if props == nil {
		return attrs, nil
	}
	if pols := mappingGet(props, "Policies"); pols != nil && pols.Kind == yaml.SequenceNode {
		for _, p := range pols.Content {
			pn := mappingGet(p, "PolicyName")
			pd := mappingGet(p, "PolicyDocument")
			if pn == nil || pd == nil {
				continue
			}
			name, ok := t.resolveString(pn)
			if !ok {
				name = logicalID + "-inline"
			}
			companions = append(companions, ir.Resource{
				Type:     "aws_iam_user_policy",
				Name:     logicalID + "-" + name,
				Provider: "aws",
				Attributes: map[string]ir.Value{
					"name":   {Raw: name, Known: true, Span: nodeSpan(t.path, pn)},
					"user":   {Raw: logicalID, Known: true, Span: nodeSpan(t.path, p)},
					"policy": jsonString(t.path, pd, t),
				},
				Span: nodeSpan(t.path, p),
			})
		}
		delete(attrs, "policies")
	}
	return attrs, companions
}

// convertKMSKey maps KeyPolicy (map) -> policy (JSON string).
func convertKMSKey(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	props := mappingGet(def, "Properties")
	if props == nil {
		return attrs, nil
	}
	if kp := mappingGet(props, "KeyPolicy"); kp != nil {
		attrs["policy"] = jsonString(t.path, kp, t)
		delete(attrs, "key_policy")
	}
	if e := mappingGet(props, "EnableKeyRotation"); e != nil {
		attrs["enable_key_rotation"] = t.resolveValue(e)
	}
	return attrs, nil
}

// convertSecurityGroup maps SecurityGroupIngress/Egress to TF ingress/egress
// block lists.
func convertSecurityGroup(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	props := mappingGet(def, "Properties")
	if props == nil {
		return attrs, nil
	}
	if gd := mappingGet(props, "GroupDescription"); gd != nil {
		attrs["description"] = t.resolveValue(gd)
		delete(attrs, "group_description")
	}
	if ing := mappingGet(props, "SecurityGroupIngress"); ing != nil {
		attrs["ingress"] = t.sgRules(ing)
		delete(attrs, "security_group_ingress")
	}
	if egr := mappingGet(props, "SecurityGroupEgress"); egr != nil {
		attrs["egress"] = t.sgRules(egr)
		delete(attrs, "security_group_egress")
	}
	if vpc := mappingGet(props, "VpcId"); vpc != nil {
		attrs["vpc_id"] = t.resolveValue(vpc)
	}
	return attrs, nil
}

// sgRules converts a CFN ingress/egress rule list to TF shape.
func (t *template) sgRules(n *yaml.Node) ir.Value {
	span := nodeSpan(t.path, n)
	var out []ir.Value
	if n.Kind == yaml.SequenceNode {
		for _, item := range n.Content {
			m := map[string]ir.Value{}
			get := func(cfn, tf string) {
				if v := mappingGet(item, cfn); v != nil {
					m[tf] = t.resolveValue(v)
				}
			}
			get("IpProtocol", "protocol")
			get("FromPort", "from_port")
			get("ToPort", "to_port")
			get("Description", "description")
			if c := mappingGet(item, "CidrIp"); c != nil {
				m["cidr_blocks"] = ir.Value{Raw: []ir.Value{t.resolveValue(c)}, Known: true, Span: nodeSpan(t.path, c)}
			}
			if c := mappingGet(item, "CidrIpv6"); c != nil {
				m["ipv6_cidr_blocks"] = ir.Value{Raw: []ir.Value{t.resolveValue(c)}, Known: true, Span: nodeSpan(t.path, c)}
			}
			if g := mappingGet(item, "SourceSecurityGroupId"); g != nil {
				m["source_security_group_id"] = t.resolveValue(g)
			}
			if g := mappingGet(item, "DestinationSecurityGroupId"); g != nil {
				m["destination_security_group_id"] = t.resolveValue(g)
			}
			out = append(out, ir.Value{Raw: m, Known: true, Span: nodeSpan(t.path, item)})
		}
	}
	return ir.Value{Raw: out, Known: true, Span: span}
}

// convertDBInstance maps the key RDS properties explicitly (generic
// conversion already snake_cases them; this is a no-op guard for clarity
// and future structural fixes).
func convertDBInstance(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	return attrs, nil
}

// convertCloudTrail maps IsLogging -> enable_logging etc.
func convertCloudTrail(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	props := mappingGet(def, "Properties")
	if props == nil {
		return attrs, nil
	}
	renames := map[string]string{
		"IsLogging":                 "enable_logging",
		"EnableLogFileValidation":   "enable_log_file_validation",
		"IsMultiRegionTrail":        "is_multi_region_trail",
		"S3BucketName":              "s3_bucket_name",
		"S3KeyPrefix":               "s3_key_prefix",
		"KMSKeyId":                  "kms_key_id",
		"CloudWatchLogsRoleArn":     "cloud_watch_logs_role_arn",
		"CloudWatchLogsLogGroupArn": "cloud_watch_logs_group_arn",
	}
	for cfn, tf := range renames {
		if n := mappingGet(props, cfn); n != nil {
			if snakeCase(cfn) != tf {
				delete(attrs, snakeCase(cfn))
			}
			attrs[tf] = t.resolveValue(n)
		}
	}
	return attrs, nil
}

// convertDynamoDBTable maps SSESpecification -> server_side_encryption.
func convertDynamoDBTable(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	props := mappingGet(def, "Properties")
	if props == nil {
		return attrs, nil
	}
	if sse := mappingGet(props, "SSESpecification"); sse != nil && sse.Kind == yaml.MappingNode {
		m := map[string]ir.Value{}
		if e := mappingGet(sse, "SSEEnabled"); e != nil {
			m["enabled"] = t.resolveValue(e)
		}
		if k := mappingGet(sse, "KMSMasterKeyId"); k != nil {
			m["kms_key_arn"] = t.resolveValue(k)
		}
		attrs["server_side_encryption"] = blockList(t.path, sse, m)
		delete(attrs, "sse_specification")
	}
	return attrs, nil
}

// convertElastiCacheRG maps AtRest/Transit encryption flags.
func convertElastiCacheRG(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	props := mappingGet(def, "Properties")
	if props == nil {
		return attrs, nil
	}
	renames := map[string]string{
		"AtRestEncryptionEnabled":  "at_rest_encryption_enabled",
		"TransitEncryptionEnabled": "transit_encryption_enabled",
		"NumCacheClusters":         "num_cache_clusters",
	}
	for cfn, tf := range renames {
		if n := mappingGet(props, cfn); n != nil {
			if snakeCase(cfn) != tf {
				delete(attrs, snakeCase(cfn))
			}
			attrs[tf] = t.resolveValue(n)
		}
	}
	return attrs, nil
}

// convertRedshiftCluster: generic conversion suffices (Encrypted,
// PubliclyAccessible map cleanly).
func convertRedshiftCluster(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	return attrs, nil
}

// convertOpenSearch maps EncryptionAtRestOptions/NodeToNodeEncryptionOptions.
func convertOpenSearch(t *template, logicalID, tfType string, attrs map[string]ir.Value, def *yaml.Node) (map[string]ir.Value, []ir.Resource) {
	props := mappingGet(def, "Properties")
	if props == nil {
		return attrs, nil
	}
	if e := mappingGet(props, "EncryptionAtRestOptions"); e != nil && e.Kind == yaml.MappingNode {
		m := map[string]ir.Value{}
		if en := mappingGet(e, "Enabled"); en != nil {
			m["enabled"] = t.resolveValue(en)
		}
		if k := mappingGet(e, "KmsKeyId"); k != nil {
			m["kms_key_id"] = t.resolveValue(k)
		}
		attrs["encrypt_at_rest"] = blockList(t.path, e, m)
		delete(attrs, "encryption_at_rest_options")
	}
	if n := mappingGet(props, "NodeToNodeEncryptionOptions"); n != nil && n.Kind == yaml.MappingNode {
		m := map[string]ir.Value{}
		if en := mappingGet(n, "Enabled"); en != nil {
			m["enabled"] = t.resolveValue(en)
		}
		attrs["node_to_node_encryption"] = blockList(t.path, n, m)
		delete(attrs, "node_to_node_encryption_options")
	}
	return attrs, nil
}
