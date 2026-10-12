resource "aws_s3_bucket" "c67" {
  bucket = "clean-67"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c67" {
  bucket = aws_s3_bucket.c67.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c67.arn
    }
  }
}
resource "aws_kms_key" "c67" {
  description = "clean-67"
  enable_key_rotation = true
}
