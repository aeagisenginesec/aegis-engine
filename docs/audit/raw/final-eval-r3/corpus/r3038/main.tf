resource "aws_kms_key" "data" {
  description = "data-key-dc74bf"
  enable_key_rotation = false
}

resource "aws_s3_bucket" "vault" {
  bucket = "vault-dc74bf"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

resource "aws_iam_user" "ops" {
  name = "ops-dc74bf"
}

resource "aws_iam_user_policy_attachment" "ops" {
  user = aws_iam_user.ops.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
