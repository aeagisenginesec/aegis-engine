resource "aws_kms_key" "vuln" {
  description         = "vuln"
  enable_key_rotation = false
}
