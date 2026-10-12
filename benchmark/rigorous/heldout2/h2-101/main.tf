resource "aws_s3_bucket" "c101" {
  bucket = "clean-101"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c101" {
  bucket = aws_s3_bucket.c101.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c101.arn
    }
  }
}
resource "aws_kms_key" "c101" {
  description = "clean-101"
  enable_key_rotation = true
}
