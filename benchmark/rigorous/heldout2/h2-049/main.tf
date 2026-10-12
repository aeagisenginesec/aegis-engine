resource "aws_s3_bucket" "c49" {
  bucket = "clean-49"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c49" {
  bucket = aws_s3_bucket.c49.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c49.arn
    }
  }
}
resource "aws_kms_key" "c49" {
  description = "clean-49"
  enable_key_rotation = true
}
