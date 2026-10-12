resource "aws_s3_bucket" "c120" {
  bucket = "clean-120"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c120" {
  bucket = aws_s3_bucket.c120.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c120.arn
    }
  }
}
resource "aws_kms_key" "c120" {
  description = "clean-120"
  enable_key_rotation = true
}
