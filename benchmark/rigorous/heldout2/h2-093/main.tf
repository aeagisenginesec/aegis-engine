resource "aws_s3_bucket" "c93" {
  bucket = "clean-93"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c93" {
  bucket = aws_s3_bucket.c93.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c93.arn
    }
  }
}
resource "aws_kms_key" "c93" {
  description = "clean-93"
  enable_key_rotation = true
}
