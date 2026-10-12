resource "aws_s3_bucket" "c127" {
  bucket = "clean-127"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c127" {
  bucket = aws_s3_bucket.c127.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c127.arn
    }
  }
}
resource "aws_kms_key" "c127" {
  description = "clean-127"
  enable_key_rotation = true
}
