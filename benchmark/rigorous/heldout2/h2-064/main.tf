resource "aws_s3_bucket" "c64" {
  bucket = "clean-64"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c64" {
  bucket = aws_s3_bucket.c64.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c64.arn
    }
  }
}
resource "aws_kms_key" "c64" {
  description = "clean-64"
  enable_key_rotation = true
}
