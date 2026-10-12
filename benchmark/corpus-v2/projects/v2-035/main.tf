resource "aws_secretsmanager_secret" "app" {
  name       = "app"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
}

output "master_secret" {
  value = aws_secretsmanager_secret.app.arn
}
