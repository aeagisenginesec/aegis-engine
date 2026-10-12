resource "aws_s3_bucket" "c68" {
  bucket = "clean-68"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c68" {
  bucket = aws_s3_bucket.c68.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c68.arn
    }
  }
}
resource "aws_kms_key" "c68" {
  description = "clean-68"
  enable_key_rotation = true
}
