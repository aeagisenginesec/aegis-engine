resource "aws_efs_file_system" "vuln" {
  encrypted  = true
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc"
}
