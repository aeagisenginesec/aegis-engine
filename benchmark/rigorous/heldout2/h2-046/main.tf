resource "aws_s3_bucket" "c46" {
  bucket = "clean-46"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c46" {
  bucket = aws_s3_bucket.c46.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c46.arn
    }
  }
}
resource "aws_kms_key" "c46" {
  description = "clean-46"
  enable_key_rotation = true
}
