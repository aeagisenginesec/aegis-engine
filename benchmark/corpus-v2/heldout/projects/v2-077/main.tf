resource "aws_kms_grant" "ops" {
  name              = "ops"
  key_id            = "arn:aws:kms:us-east-1:123456789012:key/abc"
  grantee_principal = "arn:aws:iam::123456789012:role/ops"
  operations        = ["*"]
}
