resource "aws_s3_bucket" "c78" {
  bucket = "clean-78"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c78" {
  bucket = aws_s3_bucket.c78.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c78.arn
    }
  }
}
resource "aws_kms_key" "c78" {
  description = "clean-78"
  enable_key_rotation = true
}
