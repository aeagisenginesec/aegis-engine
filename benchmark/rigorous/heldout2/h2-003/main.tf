resource "aws_s3_bucket" "c3" {
  bucket = "clean-3"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c3" {
  bucket = aws_s3_bucket.c3.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c3.arn
    }
  }
}
resource "aws_kms_key" "c3" {
  description = "clean-3"
  enable_key_rotation = true
}
