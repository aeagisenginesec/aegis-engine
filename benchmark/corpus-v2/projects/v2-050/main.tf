resource "aws_redshiftserverless_namespace" "analytics" {
  namespace_name = "analytics"
  kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
}

resource "aws_redshiftserverless_workgroup" "analytics" {
  namespace_name       = aws_redshiftserverless_namespace.analytics.namespace_name
  workgroup_name       = "analytics"
  publicly_accessible  = true
  subnet_ids           = ["subnet-0a1b2c3d"]
  security_group_ids   = ["sg-0a1b2c3d"]
}
