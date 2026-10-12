resource "aws_s3_bucket" "c111" {
  bucket = "clean-111"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c111" {
  bucket = aws_s3_bucket.c111.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c111.arn
    }
  }
}
resource "aws_kms_key" "c111" {
  description = "clean-111"
  enable_key_rotation = true
}
