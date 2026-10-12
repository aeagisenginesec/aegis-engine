resource "aws_s3_bucket" "c42" {
  bucket = "clean-42"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c42" {
  bucket = aws_s3_bucket.c42.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c42.arn
    }
  }
}
resource "aws_kms_key" "c42" {
  description = "clean-42"
  enable_key_rotation = true
}
