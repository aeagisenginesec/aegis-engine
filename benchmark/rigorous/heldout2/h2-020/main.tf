resource "aws_s3_bucket" "c20" {
  bucket = "clean-20"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c20" {
  bucket = aws_s3_bucket.c20.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c20.arn
    }
  }
}
resource "aws_kms_key" "c20" {
  description = "clean-20"
  enable_key_rotation = true
}
