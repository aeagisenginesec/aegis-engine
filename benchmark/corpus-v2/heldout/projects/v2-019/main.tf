resource "aws_kms_key" "data" {
  description         = "data"
  enable_key_rotation = true
}

resource "aws_kms_grant" "etl_full" {
  name              = "etl-full"
  key_id            = aws_kms_key.data.key_id
  grantee_principal = "arn:aws:iam::123456789012:role/etl-worker"
  operations        = ["*"]
}
