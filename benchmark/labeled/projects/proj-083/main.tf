resource "aws_secretsmanager_secret" "vuln" {
  name       = "vuln"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc"
}
