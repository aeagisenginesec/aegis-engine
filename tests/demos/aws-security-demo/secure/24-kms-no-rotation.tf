resource "aws_kms_key" "demo" {
  description         = "demo key without rotation"
  enable_key_rotation = true
}
