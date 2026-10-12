resource "aws_backup_vault" "demo" {
  name        = "demo-vault"
  kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
}
