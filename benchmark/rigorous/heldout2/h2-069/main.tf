resource "aws_s3_bucket" "c69" {
  bucket = "clean-69"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c69" {
  bucket = aws_s3_bucket.c69.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c69.arn
    }
  }
}
resource "aws_kms_key" "c69" {
  description = "clean-69"
  enable_key_rotation = true
}
