resource "aws_s3_bucket" "c62" {
  bucket = "clean-62"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c62" {
  bucket = aws_s3_bucket.c62.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c62.arn
    }
  }
}
resource "aws_kms_key" "c62" {
  description = "clean-62"
  enable_key_rotation = true
}
