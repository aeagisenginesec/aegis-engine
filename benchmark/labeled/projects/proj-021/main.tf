resource "aws_secretsmanager_secret" "vuln" {
  name       = "vuln"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc"
}
resource "aws_secretsmanager_secret_version" "v" {
  secret_id     = aws_secretsmanager_secret.vuln.id
  secret_string = "hardcoded-secret-value-123"
}
