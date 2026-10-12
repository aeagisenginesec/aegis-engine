resource "aws_s3_bucket" "c27" {
  bucket = "clean-27"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c27" {
  bucket = aws_s3_bucket.c27.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c27.arn
    }
  }
}
resource "aws_kms_key" "c27" {
  description = "clean-27"
  enable_key_rotation = true
}
