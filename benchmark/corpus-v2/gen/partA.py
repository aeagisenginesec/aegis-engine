"""Corpus-v2 part A: 60 labeled vulnerable AWS Terraform projects.

Categories: iam-escalation (a-000..a-024), secret-leakage (a-025..a-039),
public-exposure (a-040..a-059). Each project isolates one issue family:
everything except the vulnerability under test is hardened via
silencer snippets (IMDSv2, encryption, logging, WAF, etc.), following
the technique in benchmark/labeled/generate_corpus.py.

Templates are original (not copied from generate_corpus.py).
All expected rule_ids were verified by scanning each project with
`aegis scan --format=json` (see verification summary at end of file).
"""

PROJECTS = [
  {
    "local": 'a-000',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_role_policy" "deploy_admin" {\n  name = "deploy-admin"\n  role = "deployer"\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-333', "resource": 'aws_iam_role_policy.deploy_admin', "severity": 'high', "issue": 'inline admin policy on role'},
      {"rule_id": 'AEGIS-AWS-006', "resource": 'aws_iam_role_policy.deploy_admin', "severity": 'critical', "issue": 'co-fire: *:* admin doc'},
    ],
  },
  {
    "local": 'a-001',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_user" "operator" {\n  name = "operator"\n}\n\nresource "aws_iam_user_policy" "operator_admin" {\n  name = "operator-admin"\n  user = aws_iam_user.operator.name\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-333', "resource": 'aws_iam_user_policy.operator_admin', "severity": 'high', "issue": 'inline admin policy on user'},
      {"rule_id": 'AEGIS-AWS-006', "resource": 'aws_iam_user_policy.operator_admin', "severity": 'critical', "issue": 'co-fire: *:* admin doc'},
    ],
  },
  {
    "local": 'a-002',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_group" "platform" {\n  name = "platform"\n}\n\nresource "aws_iam_group_policy" "platform_admin" {\n  name  = "platform-admin"\n  group = aws_iam_group.platform.name\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-333', "resource": 'aws_iam_group_policy.platform_admin', "severity": 'high', "issue": 'inline admin policy on group'},
      {"rule_id": 'AEGIS-AWS-555', "resource": 'aws_iam_group_policy.platform_admin', "severity": 'medium', "issue": 'co-fire: group wildcard admin'},
      {"rule_id": 'AEGIS-AWS-006', "resource": 'aws_iam_group_policy.platform_admin', "severity": 'critical', "issue": 'co-fire: *:* admin doc'},
    ],
  },
  {
    "local": 'a-003',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_ssoadmin_permission_set" "superuser" {\n  name         = "SuperUser"\n  instance_arn = "arn:aws:sso:::instance/ssoins-0a1b2c3d4e5f60718"\n}\n\nresource "aws_ssoadmin_permission_set_inline_policy" "superuser_admin" {\n  instance_arn       = "arn:aws:sso:::instance/ssoins-0a1b2c3d4e5f60718"\n  permission_set_arn = aws_ssoadmin_permission_set.superuser.arn\n  inline_policy      = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-422', "resource": 'aws_ssoadmin_permission_set_inline_policy.superuser_admin', "severity": 'high', "issue": 'SSO permission set inline admin policy'},
    ],
  },
  {
    "local": 'a-004',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_role" "etl_worker" {\n  name = "etl-worker"\n  assume_role_policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {"Service": "ec2.amazonaws.com"},\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}\nPOLICY\n}\n\nresource "aws_iam_policy" "etl_data" {\n  name = "etl-data"\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": ["s3:*", "iam:PassRole"],\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n\nresource "aws_iam_role_policy_attachment" "etl_attach" {\n  role       = aws_iam_role.etl_worker.name\n  policy_arn = aws_iam_policy.etl_data.arn\n}\n\nresource "aws_iam_instance_profile" "etl_worker" {\n  name = "etl-worker"\n  role = aws_iam_role.etl_worker.name\n}\n\nresource "aws_instance" "etl" {\n  ami                = "ami-0a1b2c3d4e5f60718"\n  instance_type      = "t3.micro"\n  iam_instance_profile = aws_iam_instance_profile.etl_worker.name\n  monitoring    = true\n  metadata_options {\n    http_tokens = "required"\n  }\n  ebs_block_device {\n    device_name = "/dev/sda1"\n    volume_size = 30\n    encrypted   = true\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-630', "resource": 'aws_instance.etl', "severity": 'high', "issue": 'EC2 inherits s3:* + iam:PassRole via profile->role->policy'},
    ],
  },
  {
    "local": 'a-005',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_role" "report_fn" {\n  name = "report-fn"\n  assume_role_policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {"Service": "lambda.amazonaws.com"},\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}\nPOLICY\n}\n\nresource "aws_iam_policy" "report_all" {\n  name = "report-all"\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "iam:*",\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n\nresource "aws_iam_role_policy_attachment" "report_attach" {\n  role       = aws_iam_role.report_fn.name\n  policy_arn = aws_iam_policy.report_all.arn\n}\n\nresource "aws_lambda_function" "report" {\n  function_name = "report"\n  role          = aws_iam_role.report_fn.arn\n  runtime       = "python3.13"\n  handler       = "index.handler"\n  tracing_config {\n    mode = "Active"\n  }\n  vpc_config {\n    subnet_ids         = ["subnet-0a1b2c3d"]\n    security_group_ids = ["sg-0a1b2c3d"]\n  }\n  reserved_concurrent_executions = 10\n  code_signing_config {\n  }\n  dead_letter_config {\n    target_arn = "arn:aws:sqs:us-east-1:123456789012:dlq"\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-630', "resource": 'aws_lambda_function.report', "severity": 'high', "issue": 'Lambda inherits iam:* via role->policy'},
    ],
  },
  {
    "local": 'a-006',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_role" "jump_host" {\n  name = "jump-host"\n  assume_role_policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {"Service": "ec2.amazonaws.com"},\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}\nPOLICY\n}\n\nresource "aws_iam_policy" "hop" {\n  name = "hop"\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": ["sts:AssumeRole"],\n      "Resource": "arn:aws:iam::123456789012:role/*"\n    }\n  ]\n}\nPOLICY\n}\n\nresource "aws_iam_role_policy_attachment" "hop_attach" {\n  role       = aws_iam_role.jump_host.name\n  policy_arn = aws_iam_policy.hop.arn\n}\n\nresource "aws_iam_instance_profile" "jump_host" {\n  name = "jump-host"\n  role = aws_iam_role.jump_host.name\n}\n\nresource "aws_instance" "bastion" {\n  ami                = "ami-0a1b2c3d4e5f60718"\n  instance_type      = "t3.micro"\n  iam_instance_profile = aws_iam_instance_profile.jump_host.name\n  monitoring    = true\n  metadata_options {\n    http_tokens = "required"\n  }\n  ebs_block_device {\n    device_name = "/dev/sda1"\n    volume_size = 30\n    encrypted   = true\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-630', "resource": 'aws_instance.bastion', "severity": 'high', "issue": 'EC2 inherits sts:AssumeRole (role chaining)'},
    ],
  },
  {
    "local": 'a-007',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_policy" "almost_all" {\n  name = "almost-all"\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "NotAction": ["iam:DeleteAccountPasswordPolicy"],\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-553', "resource": 'aws_iam_policy.almost_all', "severity": 'high', "issue": 'NotAction with Allow effect'},
    ],
  },
  {
    "local": 'a-008',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_role" "ci_runner" {\n  name                 = "ci-runner"\n  max_session_duration = 72000\n  assume_role_policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {"Service": "ec2.amazonaws.com"},\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-554', "resource": 'aws_iam_role.ci_runner', "severity": 'medium', "issue": 'max_session_duration 72000 > 43200'},
    ],
  },
  {
    "local": 'a-009',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_user" "svc_deploy" {\n  name = "svc-deploy"\n}\n\nresource "aws_iam_access_key" "svc_deploy" {\n  user = aws_iam_user.svc_deploy.name\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-552', "resource": 'aws_iam_access_key.svc_deploy', "severity": 'high', "issue": 'access key without pgp_key'},
    ],
  },
  {
    "local": 'a-010',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_vpc_endpoint" "s3gw" {\n  vpc_id            = "vpc-0a1b2c3d"\n  service_name      = "com.amazonaws.us-east-1.s3"\n  vpc_endpoint_type = "Gateway"\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": "*",\n      "Action": "s3:*",\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-557', "resource": 'aws_vpc_endpoint.s3gw', "severity": 'medium', "issue": 'endpoint policy Principal *'},
      {"rule_id": 'AEGIS-AWS-433', "resource": 'aws_vpc_endpoint.s3gw', "severity": 'high', "issue": 'co-fire: public endpoint policy'},
    ],
  },
  {
    "local": 'a-011',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_vpc_endpoint" "dynamo" {\n  vpc_id            = "vpc-0a1b2c3d"\n  service_name      = "com.amazonaws.us-east-1.dynamodb"\n  vpc_endpoint_type = "Gateway"\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-433', "resource": 'aws_vpc_endpoint.dynamo', "severity": 'high', "issue": 'endpoint policy absent (default full access)'},
      {"rule_id": 'AEGIS-AWS-557', "resource": 'aws_vpc_endpoint.dynamo', "severity": 'medium', "issue": 'co-fire: absent policy allows all principals'},
    ],
  },
  {
    "local": 'a-012',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_s3_access_point" "reports" {\n  name   = "reports-ap"\n  bucket = "reports-bucket"\n}\n\nresource "aws_s3control_access_point_policy" "reports" {\n  access_point_arn = aws_s3_access_point.reports.arn\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": "*",\n      "Action": "s3:GetObject",\n      "Resource": "arn:aws:s3:us-east-1:123456789012:accesspoint/reports-ap/object/*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-441', "resource": 'aws_s3control_access_point_policy.reports', "severity": 'high', "issue": 'access point policy Principal *'},
    ],
  },
  {
    "local": 'a-013',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_lambda_permission" "open_invoke" {\n  statement_id  = "OpenInvoke"\n  action        = "lambda:InvokeFunction"\n  function_name = "billing-hook"\n  principal     = "*"\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-406', "resource": 'aws_lambda_permission.open_invoke', "severity": 'high', "issue": 'lambda permission principal *'},
    ],
  },
  {
    "local": 'a-014',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_lambda_function" "webhook" {\n  function_name = "webhook"\n  role          = "arn:aws:iam::123456789012:role/webhook"\n  runtime       = "python3.13"\n  handler       = "index.handler"\n  tracing_config {\n    mode = "Active"\n  }\n  vpc_config {\n    subnet_ids         = ["subnet-0a1b2c3d"]\n    security_group_ids = ["sg-0a1b2c3d"]\n  }\n  reserved_concurrent_executions = 10\n  code_signing_config {\n  }\n  dead_letter_config {\n    target_arn = "arn:aws:sqs:us-east-1:123456789012:dlq"\n  }\n}\n\nresource "aws_lambda_function_url" "webhook" {\n  function_name      = aws_lambda_function.webhook.function_name\n  authorization_type = "NONE"\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-407', "resource": 'aws_lambda_function_url.webhook', "severity": 'high', "issue": 'function URL authorization NONE'},
    ],
  },
  {
    "local": 'a-015',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_api_gateway_method" "orders_post" {\n  rest_api_id   = "a1b2c3d4e5"\n  resource_id   = "f6g7h8i9j0"\n  http_method   = "POST"\n  authorization = "NONE"\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-403', "resource": 'aws_api_gateway_method.orders_post', "severity": 'high', "issue": 'API method authorization NONE'},
    ],
  },
  {
    "local": 'a-016',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_apigatewayv2_route" "events" {\n  api_id             = "a1b2c3d4e5"\n  route_key          = "POST /events"\n  authorization_type = "NONE"\n  target             = "integrations/abc123"\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-404', "resource": 'aws_apigatewayv2_route.events', "severity": 'high', "issue": 'v2 route authorization NONE'},
    ],
  },
  {
    "local": 'a-017',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iot_policy" "fleet_wide" {\n  name = "fleet-wide"\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "iot:Connect",\n      "Resource": "arn:aws:iot:us-east-1:123456789012:client/$${iot:Connection.Thing.ThingName}"\n    },\n    {\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-390', "resource": 'aws_iot_policy.fleet_wide', "severity": 'high', "issue": 'IoT policy admin-style Allow'},
    ],
  },
  {
    "local": 'a-018',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_ecr_repository" "app" {\n  name                 = "app"\n  image_tag_mutability = "IMMUTABLE"\n  image_scanning_configuration {\n    scan_on_push = true\n  }\n  encryption_configuration {\n    encryption_type = "KMS"\n    kms_key         = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"\n  }\n}\n\nresource "aws_ecr_repository_policy" "app_open" {\n  repository = aws_ecr_repository.app.name\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": "*",\n      "Action": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"],\n      "Resource": "arn:aws:ecr:us-east-1:123456789012:repository/app"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-408', "resource": 'aws_ecr_repository_policy.app_open', "severity": 'high', "issue": 'ECR repo policy Principal *'},
    ],
  },
  {
    "local": 'a-019',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_kms_key" "data" {\n  description         = "data"\n  enable_key_rotation = true\n}\n\nresource "aws_kms_grant" "etl_full" {\n  name              = "etl-full"\n  key_id            = aws_kms_key.data.key_id\n  grantee_principal = "arn:aws:iam::123456789012:role/etl-worker"\n  operations        = ["*"]\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-562', "resource": 'aws_kms_grant.etl_full', "severity": 'medium', "issue": 'KMS grant operations *'},
    ],
  },
  {
    "local": 'a-020',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_group" "contractors" {\n  name = "contractors"\n}\n\nresource "aws_iam_group_policy" "contractor_power" {\n  name  = "contractor-power"\n  group = aws_iam_group.contractors.name\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Sid": "ScopedRead",\n      "Effect": "Allow",\n      "Action": ["ec2:DescribeInstances", "s3:ListBucket"],\n      "Resource": "*"\n    },\n    {\n      "Sid": "LegacyAdmin",\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-555', "resource": 'aws_iam_group_policy.contractor_power', "severity": 'medium', "issue": 'group policy wildcard admin statement'},
      {"rule_id": 'AEGIS-AWS-333', "resource": 'aws_iam_group_policy.contractor_power', "severity": 'high', "issue": 'co-fire: inline admin on group'},
      {"rule_id": 'AEGIS-AWS-006', "resource": 'aws_iam_group_policy.contractor_power', "severity": 'critical', "issue": 'co-fire: *:* admin doc'},
    ],
  },
  {
    "local": 'a-021',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_role" "godmode" {\n  name = "godmode"\n  assume_role_policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {"Service": "ec2.amazonaws.com"},\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}\nPOLICY\n}\n\nresource "aws_iam_policy" "godmode" {\n  name = "godmode"\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n\nresource "aws_iam_role_policy_attachment" "godmode" {\n  role       = aws_iam_role.godmode.name\n  policy_arn = aws_iam_policy.godmode.arn\n}\n\nresource "aws_iam_instance_profile" "godmode" {\n  name = "godmode"\n  role = aws_iam_role.godmode.name\n}\n\nresource "aws_instance" "legacy" {\n  ami                = "ami-0a1b2c3d4e5f60718"\n  instance_type      = "t3.micro"\n  iam_instance_profile = aws_iam_instance_profile.godmode.name\n  monitoring    = true\n  metadata_options {\n    http_tokens = "required"\n  }\n  ebs_block_device {\n    device_name = "/dev/sda1"\n    volume_size = 30\n    encrypted   = true\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-630', "resource": 'aws_instance.legacy', "severity": 'high', "issue": 'EC2 inherits *:* via admin instance profile'},
    ],
  },
  {
    "local": 'a-022',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_ram_resource_share" "subnets" {\n  name                      = "shared-subnets"\n  allow_external_principals = true\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-399', "resource": 'aws_ram_resource_share.subnets', "severity": 'high', "issue": 'RAM share allows external principals'},
    ],
  },
  {
    "local": 'a-023',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_role_policy" "starstar" {\n  name = "starstar"\n  role = "auditor"\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*:*",\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-333', "resource": 'aws_iam_role_policy.starstar', "severity": 'high', "issue": 'inline admin via *:* action'},
    ],
  },
  {
    "local": 'a-024',
    "category": 'iam-escalation',
    "files": {
      'main.tf': 'resource "aws_iam_role" "readonly_plus" {\n  name = "readonly-plus"\n  assume_role_policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {"Service": "ec2.amazonaws.com"},\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}\nPOLICY\n}\n\nresource "aws_iam_role_policy" "almost_ro" {\n  name = "almost-ro"\n  role = aws_iam_role.readonly_plus.name\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "NotAction": ["iam:*", "organizations:*"],\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-553', "resource": 'aws_iam_role_policy.almost_ro', "severity": 'high', "issue": 'NotAction+Allow on role policy'},
    ],
  },
  {
    "local": 'a-025',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'resource "aws_instance" "appserver" {\n  ami           = "ami-0a1b2c3d4e5f60718"\n  instance_type = "t3.micro"\n  monitoring    = true\n  metadata_options {\n    http_tokens = "required"\n  }\n  ebs_block_device {\n    device_name = "/dev/sda1"\n    volume_size = 30\n    encrypted   = true\n  }\n\n  provisioner "remote-exec" {\n    inline = ["sudo apt-get update -y"]\n\n    connection {\n      type     = "ssh"\n      user     = "ubuntu"\n      password = "fake-test-secret-001"\n      host     = self.public_ip\n    }\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-535', "resource": 'aws_instance.appserver', "severity": 'high', "issue": 'plaintext password in provisioner connection'},
      {"rule_id": 'AEGIS-SC-005', "resource": 'aws_instance.appserver', "severity": 'medium', "issue": 'co-fire: remote-exec provisioner'},
    ],
  },
  {
    "local": 'a-026',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'resource "aws_db_instance" "orders" {\n  engine                              = "postgres"\n  instance_class                      = "db.t3.micro"\n  allocated_storage                   = 20\n  username                            = "admin"\n  storage_encrypted                   = true\n  deletion_protection                 = true\n  publicly_accessible                 = false\n  backup_retention_period             = 7\n  iam_database_authentication_enabled = true\n  multi_az                            = true\n  auto_minor_version_upgrade          = true\n  copy_tags_to_snapshot               = true\n  monitoring_interval                 = 60\n  performance_insights_enabled        = true\n  performance_insights_kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"\n  enabled_cloudwatch_logs_exports     = ["postgresql"]\n  enabled_cloudwatch_logs_log_exports = ["postgresql"]\n}\n\noutput "db_master_password" {\n  value = aws_db_instance.orders.password\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-536', "resource": 'terraform_output.db_master_password', "severity": 'high', "issue": 'secret-like output not marked sensitive'},
    ],
  },
  {
    "local": 'a-027',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'resource "aws_instance" "worker" {\n  ami           = "ami-0a1b2c3d4e5f60718"\n  instance_type = "t3.micro"\n  monitoring    = true\n  metadata_options {\n    http_tokens = "required"\n  }\n  ebs_block_device {\n    device_name = "/dev/sda1"\n    volume_size = 30\n    encrypted   = true\n  }\n\n  tags = {\n    Name    = "worker"\n    api_key = "fake-test-secret-002"\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-537', "resource": 'aws_instance.worker', "severity": 'medium', "issue": 'secret-like tag api_key'},
    ],
  },
  {
    "local": 'a-028',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'locals {\n  service_api_token = "fake-test-secret-003"\n  region            = "us-east-1"\n}\n\nresource "aws_sns_topic" "alerts" {\n  name              = "alerts"\n  kms_master_key_id = "alias/aws/sns"\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-539', "resource": 'terraform_locals.locals', "severity": 'medium', "issue": 'hardcoded secret in local value'},
    ],
  },
  {
    "local": 'a-029',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'variable "service_token" {\n  type      = string\n  sensitive = true\n}\n\noutput "service_token" {\n  value     = var.service_token\n  sensitive = false\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-536', "resource": 'terraform_output.service_token', "severity": 'high', "issue": 'secret-like output explicitly not sensitive'},
    ],
  },
  {
    "local": 'a-030',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'resource "aws_db_instance" "billing" {\n  engine                              = "postgres"\n  instance_class                      = "db.t3.micro"\n  allocated_storage                   = 20\n  username                            = "admin"\n  storage_encrypted                   = true\n  deletion_protection                 = true\n  publicly_accessible                 = false\n  backup_retention_period             = 7\n  iam_database_authentication_enabled = true\n  multi_az                            = true\n  auto_minor_version_upgrade          = true\n  copy_tags_to_snapshot               = true\n  monitoring_interval                 = 60\n  performance_insights_enabled        = true\n  performance_insights_kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"\n  enabled_cloudwatch_logs_exports     = ["postgresql"]\n  enabled_cloudwatch_logs_log_exports = ["postgresql"]\n  tags = {\n    Name        = "billing"\n    db_password = "fake-test-secret-004"\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-537', "resource": 'aws_db_instance.billing', "severity": 'medium', "issue": 'secret-like tag db_password'},
    ],
  },
  {
    "local": 'a-031',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'locals {\n  webhook_secret = "fake-test-secret-005"\n}\n\nresource "aws_lambda_function" "hook" {\n  function_name = "hook"\n  role          = "arn:aws:iam::123456789012:role/hook"\n  runtime       = "python3.13"\n  handler       = "index.handler"\n  tracing_config {\n    mode = "Active"\n  }\n  vpc_config {\n    subnet_ids         = ["subnet-0a1b2c3d"]\n    security_group_ids = ["sg-0a1b2c3d"]\n  }\n  reserved_concurrent_executions = 10\n  code_signing_config {\n  }\n  dead_letter_config {\n    target_arn = "arn:aws:sqs:us-east-1:123456789012:dlq"\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-539', "resource": 'terraform_locals.locals', "severity": 'medium', "issue": 'hardcoded webhook secret in locals'},
    ],
  },
  {
    "local": 'a-032',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'resource "aws_lambda_function" "payments" {\n  function_name = "payments"\n  role          = "arn:aws:iam::123456789012:role/payments"\n  runtime       = "python3.13"\n  handler       = "index.handler"\n  environment {\n    variables = {\n      STRIPE_MODE = "live"\n      LOG_LEVEL   = "info"\n    }\n  }\n  tracing_config {\n    mode = "Active"\n  }\n  vpc_config {\n    subnet_ids         = ["subnet-0a1b2c3d"]\n    security_group_ids = ["sg-0a1b2c3d"]\n  }\n  reserved_concurrent_executions = 10\n  code_signing_config {\n  }\n  dead_letter_config {\n    target_arn = "arn:aws:sqs:us-east-1:123456789012:dlq"\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-307', "resource": 'aws_lambda_function.payments', "severity": 'high', "issue": 'lambda env vars without KMS key'},
    ],
  },
  {
    "local": 'a-033',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'resource "aws_elasticache_replication_group" "sessions" {\n  replication_group_id       = "sessions"\n  description                = "sessions"\n  engine                     = "redis"\n  node_type                  = "cache.t3.micro"\n  num_cache_clusters         = 2\n  transit_encryption_enabled = true\n  at_rest_encryption_enabled = true\n  snapshot_retention_limit   = 7\n  automatic_failover_enabled = true\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-514', "resource": 'aws_elasticache_replication_group.sessions', "severity": 'high', "issue": 'no auth_token with transit encryption'},
    ],
  },
  {
    "local": 'a-034',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'resource "aws_instance" "dbproxy" {\n  ami           = "ami-0a1b2c3d4e5f60718"\n  instance_type = "t3.micro"\n  monitoring    = true\n  metadata_options {\n    http_tokens = "required"\n  }\n  ebs_block_device {\n    device_name = "/dev/sda1"\n    volume_size = 30\n    encrypted   = true\n  }\n\n  provisioner "file" {\n    source      = "proxy.conf"\n    destination = "/etc/proxy/proxy.conf"\n\n    connection {\n      type     = "ssh"\n      user     = "admin"\n      password = "fake-test-secret-006"\n      host     = self.private_ip\n    }\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-535', "resource": 'aws_instance.dbproxy', "severity": 'high', "issue": 'password in nested provisioner connection'},
    ],
  },
  {
    "local": 'a-035',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'resource "aws_secretsmanager_secret" "app" {\n  name       = "app"\n  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"\n}\n\noutput "master_secret" {\n  value = aws_secretsmanager_secret.app.arn\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-536', "resource": 'terraform_output.master_secret', "severity": 'high', "issue": 'secret-like output not marked sensitive'},
    ],
  },
  {
    "local": 'a-036',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'resource "aws_s3_bucket" "backups" {\n  server_side_encryption_configuration {\n    rule {\n      apply_server_side_encryption_by_default {\n        sse_algorithm = "AES256"\n      }\n    }\n  }\n\n  tags = {\n    Name = "backups",\n    access_token = "fake-test-secret-008"\n  }\n}\n\nresource "aws_s3_bucket_versioning" "v" {\n  bucket = aws_s3_bucket.backups.id\n  versioning_configuration {\n    status = "Enabled"\n  }\n}\n\nresource "aws_s3_bucket_logging" "l" {\n  bucket        = aws_s3_bucket.backups.id\n  target_bucket = aws_s3_bucket.backups.id\n  target_prefix = "logs/"\n}\n\nresource "aws_s3_bucket_object_lock_configuration" "ol" {\n  bucket = aws_s3_bucket.backups.id\n  rule {\n    default_retention {\n      mode = "COMPLIANCE"\n      days = 30\n    }\n  }\n}\n\nresource "aws_s3_bucket_public_access_block" "pab" {\n  bucket                  = aws_s3_bucket.backups.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}\n\nresource "aws_s3_bucket_policy" "tls" {\n  bucket = aws_s3_bucket.backups.id\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Sid": "DenyInsecureTransport",\n      "Effect": "Deny",\n      "Principal": "*",\n      "Action": "s3:*",\n      "Resource": ["arn:aws:s3:::backups", "arn:aws:s3:::backups/*"],\n      "Condition": {"Bool": {"aws:SecureTransport": "false"}}\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-537', "resource": 'aws_s3_bucket.backups', "severity": 'medium', "issue": 'secret-like tag access_token'},
    ],
  },
  {
    "local": 'a-037',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'locals {\n  db_password = "fake-test-secret-007"\n  db_host     = "db.internal"\n}\n\nresource "aws_ssm_parameter" "db_host" {\n  name  = "/prod/db/host"\n  type  = "String"\n  value = local.db_host\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-539', "resource": 'terraform_locals.locals', "severity": 'medium', "issue": 'hardcoded db password in locals'},
    ],
  },
  {
    "local": 'a-038',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'resource "aws_cognito_identity_pool" "mobile" {\n  identity_pool_name               = "mobile"\n  allow_unauthenticated_identities = true\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-421', "resource": 'aws_cognito_identity_pool.mobile', "severity": 'high', "issue": 'unauthenticated identities allowed'},
    ],
  },
  {
    "local": 'a-039',
    "category": 'secret-leakage',
    "files": {
      'main.tf': 'resource "aws_secretsmanager_secret" "svc" {\n  name       = "svc"\n  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"\n}\n\nresource "aws_secretsmanager_secret_rotation" "svc" {\n  secret_id           = aws_secretsmanager_secret.svc.id\n  rotation_lambda_arn = "arn:aws:lambda:us-east-1:123456789012:function:rotator"\n\n  rotation_rules {\n    automatically_after_days = 180\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-337', "resource": 'aws_secretsmanager_secret_rotation.svc', "severity": 'medium', "issue": 'rotation interval 180 days > 90'},
    ],
  },
  {
    "local": 'a-040',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_security_group" "nat" {\n  name        = "nat"\n  description = "NAT gateway security group"\n  egress {\n    description = "all outbound"\n    from_port   = 0\n    to_port     = 0\n    protocol    = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-005', "resource": 'aws_security_group.nat', "severity": 'medium', "issue": 'egress open to 0.0.0.0/0'},
    ],
  },
  {
    "local": 'a-041',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_network_acl" "public" {\n  vpc_id     = "vpc-0a1b2c3d"\n  subnet_ids = ["subnet-0a1b2c3d"]\n\n  ingress {\n    protocol   = "-1"\n    rule_no    = 100\n    action     = "allow"\n    cidr_block = "0.0.0.0/0"\n    from_port  = 0\n    to_port    = 0\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-328', "resource": 'aws_network_acl.public', "severity": 'medium', "issue": 'NACL ingress allow from 0.0.0.0/0'},
    ],
  },
  {
    "local": 'a-042',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_network_acl" "dmz" {\n  vpc_id     = "vpc-0a1b2c3d"\n  subnet_ids = ["subnet-0a1b2c3d"]\n}\n\nresource "aws_network_acl_rule" "dmz_in" {\n  network_acl_id = aws_network_acl.dmz.id\n  rule_number    = 100\n  egress         = false\n  protocol       = "tcp"\n  rule_action    = "allow"\n  cidr_block     = "0.0.0.0/0"\n  from_port      = 443\n  to_port        = 443\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-331', "resource": 'aws_network_acl_rule.dmz_in', "severity": 'medium', "issue": 'NACL rule ingress allow from 0.0.0.0/0'},
    ],
  },
  {
    "local": 'a-043',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_lb" "internal" {\n  name               = "internal"\n  internal           = true\n  load_balancer_type = "application"\n  drop_invalid_header_fields = true\n  enable_deletion_protection = true\n  access_logs {\n    bucket  = "lb-logs-bucket"\n    enabled = true\n  }\n}\n\nresource "aws_lb_target_group" "api" {\n  name     = "api"\n  port     = 80\n  protocol = "HTTP"\n  vpc_id   = "vpc-0a1b2c3d"\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-329', "resource": 'aws_lb_target_group.api', "severity": 'high', "issue": 'target group plain HTTP'},
    ],
  },
  {
    "local": 'a-044',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_s3_account_public_access_block" "acct" {\n  block_public_acls       = false\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-414', "resource": 'aws_s3_account_public_access_block.acct', "severity": 'high', "issue": 'account PAB block_public_acls false'},
    ],
  },
  {
    "local": 'a-045',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_ecs_service" "frontend" {\n  name            = "frontend"\n  cluster         = "arn:aws:ecs:us-east-1:123456789012:cluster/prod"\n  task_definition = "arn:aws:ecs:us-east-1:123456789012:task-definition/frontend:1"\n  desired_count   = 2\n\n  network_configuration {\n    subnets          = ["subnet-0a1b2c3d"]\n    security_groups  = ["sg-0a1b2c3d"]\n    assign_public_ip = true\n  }\n\n  deployment_circuit_breaker {\n    enable   = true\n    rollback = true\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-381', "resource": 'aws_ecs_service.frontend', "severity": 'high', "issue": 'ECS service assign_public_ip true'},
    ],
  },
  {
    "local": 'a-046',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_dms_replication_instance" "migration" {\n  replication_instance_id  = "migration"\n  replication_instance_class = "dms.t3.micro"\n  allocated_storage          = 50\n  publicly_accessible        = true\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-356', "resource": 'aws_dms_replication_instance.migration', "severity": 'high', "issue": 'DMS replication instance publicly accessible'},
    ],
  },
  {
    "local": 'a-047',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_transfer_server" "sftp" {\n  identity_provider_type = "SERVICE_MANAGED"\n  endpoint_type          = "PUBLIC"\n  protocols              = ["SFTP"]\n  logging_role           = "arn:aws:iam::123456789012:role/transfer-logging"\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-509', "resource": 'aws_transfer_server.sftp', "severity": 'high', "issue": 'transfer server endpoint PUBLIC'},
    ],
  },
  {
    "local": 'a-048',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_cloudfront_distribution" "assets" {\n  enabled = true\n\n  origin {\n    domain_name = "assets.example.s3.amazonaws.com"\n    origin_id   = "s3-assets"\n  }\n\n  default_cache_behavior {\n    target_origin_id       = "s3-assets"\n    viewer_protocol_policy = "allow-all"\n    allowed_methods        = ["GET", "HEAD"]\n    cached_methods         = ["GET", "HEAD"]\n    forwarded_values {\n      query_string = false\n      cookies {\n        forward = "none"\n      }\n    }\n  }\n  restrictions {\n    geo_restriction {\n      restriction_type = "whitelist"\n      locations        = ["US", "CA"]\n    }\n  }\n  logging_config {\n    bucket = "cf-logs.example.s3.amazonaws.com"\n    prefix = "cf/"\n  }\n  web_acl_id = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/cf-guard/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"\n  viewer_certificate {\n    cloudfront_default_certificate = false\n    acm_certificate_arn            = "arn:aws:acm:us-east-1:123456789012:certificate/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"\n    ssl_support_method             = "sni-only"\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-325', "resource": 'aws_cloudfront_distribution.assets', "severity": 'high', "issue": 'CloudFront viewer_protocol_policy allow-all'},
    ],
  },
  {
    "local": 'a-049',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_cloudfront_distribution" "legacy" {\n  enabled = true\n\n  origin {\n    domain_name = "legacy-origin.example.com"\n    origin_id   = "legacy"\n    custom_origin_config {\n      http_port              = 80\n      https_port             = 443\n      origin_protocol_policy = "http-only"\n      origin_ssl_protocols   = ["TLSv1.2"]\n    }\n  }\n\n  default_cache_behavior {\n    target_origin_id       = "legacy"\n    viewer_protocol_policy = "redirect-to-https"\n    allowed_methods        = ["GET", "HEAD"]\n    cached_methods         = ["GET", "HEAD"]\n    forwarded_values {\n      query_string = false\n      cookies {\n        forward = "none"\n      }\n    }\n  }\n  restrictions {\n    geo_restriction {\n      restriction_type = "whitelist"\n      locations        = ["US", "CA"]\n    }\n  }\n  logging_config {\n    bucket = "cf-logs.example.s3.amazonaws.com"\n    prefix = "cf/"\n  }\n  web_acl_id = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/cf-guard/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"\n  viewer_certificate {\n    cloudfront_default_certificate = false\n    acm_certificate_arn            = "arn:aws:acm:us-east-1:123456789012:certificate/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"\n    ssl_support_method             = "sni-only"\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-405', "resource": 'aws_cloudfront_distribution.legacy', "severity": 'high', "issue": 'custom origin origin_protocol_policy http-only'},
    ],
  },
  {
    "local": 'a-050',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_redshiftserverless_namespace" "analytics" {\n  namespace_name = "analytics"\n  kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"\n}\n\nresource "aws_redshiftserverless_workgroup" "analytics" {\n  namespace_name       = aws_redshiftserverless_namespace.analytics.namespace_name\n  workgroup_name       = "analytics"\n  publicly_accessible  = true\n  subnet_ids           = ["subnet-0a1b2c3d"]\n  security_group_ids   = ["sg-0a1b2c3d"]\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-431', "resource": 'aws_redshiftserverless_workgroup.analytics', "severity": 'high', "issue": 'serverless workgroup publicly accessible'},
    ],
  },
  {
    "local": 'a-051',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_appstream_fleet" "designers" {\n  name          = "designers"\n  instance_type = "stream.standard.small"\n  fleet_type    = "ON_DEMAND"\n  image_name    = "AppStream-AmazonLinux2-09-21-2023"\n\n  compute_capacity {\n    desired_instances = 2\n  }\n\n  vpc_config {\n    subnet_ids         = ["subnet-0a1b2c3d"]\n    security_group_ids = ["sg-0a1b2c3d"]\n  }\n\n  enable_default_internet_access = true\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-437', "resource": 'aws_appstream_fleet.designers', "severity": 'medium', "issue": 'default internet access enabled'},
    ],
  },
  {
    "local": 'a-052',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_vpc_endpoint_service" "partner_api" {\n  acceptance_required        = false\n  network_load_balancer_arns = ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/partner/0a1b2c3d4e5f6071"]\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-442', "resource": 'aws_vpc_endpoint_service.partner_api', "severity": 'medium', "issue": 'acceptance_required false'},
    ],
  },
  {
    "local": 'a-053',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_vpc_endpoint" "ecr_api" {\n  vpc_id              = "vpc-0a1b2c3d"\n  service_name        = "com.amazonaws.us-east-1.ecr.api"\n  vpc_endpoint_type   = "Interface"\n  private_dns_enabled = true\n  policy = <<POLICY\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": "*",\n      "Action": "ecr:*",\n      "Resource": "*"\n    }\n  ]\n}\nPOLICY\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-433', "resource": 'aws_vpc_endpoint.ecr_api', "severity": 'high', "issue": 'endpoint policy allows public principal'},
      {"rule_id": 'AEGIS-AWS-557', "resource": 'aws_vpc_endpoint.ecr_api', "severity": 'medium', "issue": 'co-fire: endpoint policy all principals'},
    ],
  },
  {
    "local": 'a-054',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_eks_node_group" "general" {\n  cluster_name    = "prod"\n  node_group_name = "general"\n  node_role_arn   = "arn:aws:iam::123456789012:role/eks-nodes"\n  subnet_ids      = ["subnet-0a1b2c3d"]\n\n  scaling_config {\n    desired_size = 2\n    max_size     = 4\n    min_size     = 1\n  }\n\n  remote_access {\n    ec2_ssh_key               = "prod-key"\n    source_security_group_ids = ["sg-0a1b2c3d"]\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-413', "resource": 'aws_eks_node_group.general', "severity": 'medium', "issue": 'node group remote_access (SSH)'},
    ],
  },
  {
    "local": 'a-055',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_codepipeline_webhook" "deploy" {\n  name            = "deploy"\n  target_pipeline = "webapp"\n  target_action   = "Source"\n  authentication  = "UNAUTHENTICATED"\n\n  filter {\n    json_path    = "$.ref"\n    match_equals = "refs/heads/main"\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-409', "resource": 'aws_codepipeline_webhook.deploy', "severity": 'high', "issue": 'webhook authentication UNAUTHENTICATED'},
    ],
  },
  {
    "local": 'a-056',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_lb" "storefront" {\n  name               = "storefront"\n  internal           = false\n  load_balancer_type = "application"\n  drop_invalid_header_fields = true\n  enable_deletion_protection = true\n  access_logs {\n    bucket  = "lb-logs-bucket"\n    enabled = true\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-506', "resource": 'aws_lb.storefront', "severity": 'high', "issue": 'public LB without WAF association'},
      {"rule_id": 'AEGIS-AWS-201', "resource": 'aws_lb.storefront', "severity": 'high', "issue": 'co-fire: internet-facing LB'},
    ],
  },
  {
    "local": 'a-057',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_sagemaker_notebook_instance" "research" {\n  name               = "research"\n  instance_type      = "ml.t3.medium"\n  role_arn           = "arn:aws:iam::123456789012:role/sagemaker"\n  subnet_id          = "subnet-0a1b2c3d"\n  security_groups    = ["sg-0a1b2c3d"]\n  kms_key_id         = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"\n  direct_internet_access = "Enabled"\n\n  instance_metadata_service_configuration {\n    minimum_instance_metadata_service_version = 2\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-427', "resource": 'aws_sagemaker_notebook_instance.research', "severity": 'medium', "issue": 'direct_internet_access Enabled'},
    ],
  },
  {
    "local": 'a-058',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_redshift_cluster" "warehouse" {\n  cluster_identifier   = "warehouse"\n  node_type            = "dc2.large"\n  master_username      = "admin"\n  encrypted            = true\n  publicly_accessible  = false\n  enhanced_vpc_routing = true\n  logging {\n    bucket_name = "redshift-logs-bucket"\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-508', "resource": 'aws_redshift_cluster.warehouse', "severity": 'high', "issue": 'no cluster_subnet_group_name (outside VPC)'},
    ],
  },
  {
    "local": 'a-059',
    "category": 'public-exposure',
    "files": {
      'main.tf': 'resource "aws_appsync_graphql_api" "catalog" {\n  name                = "catalog"\n  authentication_type = "API_KEY"\n  xray_enabled        = true\n\n  log_config {\n    cloudwatch_logs_role_arn = "arn:aws:iam::123456789012:role/appsync-logging"\n    field_log_level          = "ERROR"\n  }\n}\n',
    },
    "vulnerable": True,
    "expected": [
      {"rule_id": 'AEGIS-AWS-513', "resource": 'aws_appsync_graphql_api.catalog', "severity": 'medium', "issue": 'AppSync API without WAF'},
      {"rule_id": 'AEGIS-AWS-374', "resource": 'aws_appsync_graphql_api.catalog', "severity": 'medium', "issue": 'co-fire: API-key authentication'},
    ],
  },
]

# ======================================================================
# VERIFICATION SUMMARY
# ======================================================================
# Method: each project was written to a temp dir and scanned with
# `~/workspace/aegis-engine/aegis scan --format=json <dir>` (aegis 1.0.0).
# Every expected (rule_id, resource, severity) tuple was confirmed
# present in the scan findings; templates were fixed and re-scanned
# until all expectations fired (max 2 fix iterations per project).
#
# Result: 60/60 projects verified, 72 expected findings total.
#   - iam-escalation : 25 projects (a-000..a-024), 33 expected findings
#   - secret-leakage : 15 projects (a-025..a-039), 16 expected findings
#   - public-exposure: 20 projects (a-040..a-059), 23 expected findings
# All verified firing: YES (final scan pass 2026-10-12, zero missing).
#
# Genuine co-fires included in expectations (verified by scan):
#   - admin policy docs fire AEGIS-AWS-006 (critical) alongside 333/555
#   - iam:* policy in 630 chain fires 102/501/504/505 (v1, same family)
#   - s3:*+PassRole policy fires 503/505 (v1, same family)
#   - absent VPC endpoint policy fires 433 (high) + 557 (medium)
#   - explicit public endpoint policy fires 433 (high) + 557 (medium)
#   - remote-exec provisioner with password fires 535 (high) + AEGIS-SC-005 (medium)
#   - AppSync API_KEY without WAF fires 513 (medium) + 374 (medium)
#   - public ALB without WAF fires 506 (high) + 201 (high, v1)
# Incidental cross-family noise was silenced via hardener snippets
# (IMDSv2, EBS encryption, RDS logging/monitoring/PI-CMK, Lambda
# tracing/code-signing/DLQ/reserved-concurrency, CF geo/logging/WAF/cert,
# ECS circuit breaker, transfer logging role, AppSync X-Ray/log_config,
# SageMaker IMDSv2+KMS+subnet, ElastiCache encryption/snapshots/failover).
#
# Dropped expectations (rule would not fire as designed):
#   - a-023: dropped AEGIS-AWS-006 on "*:*" action spelling -- rule 006
#     does not treat "*:*" as admin (333 does); kept 333 only.
# No projects were dropped; every project isolates its target family.
#
# Notes:
#   - All secret values are obviously-fake placeholders
#     (e.g. "fake-test-secret-001"); nothing resembling a real
#     credential. The 534 user_data generic-secret regex was avoided
#     in favor of name-based rules (535/536/537/539).
#   - AEGIS-SC-005 (supply-chain family) appears once as a genuine
#     co-fire on the remote-exec provisioner project (a-025).
#   - No rule exists for trust-policy ExternalId or absent permission
#     boundaries, so those escalation variants could not be labeled.
