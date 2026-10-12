resource "aws_s3_bucket" "c87" {
  bucket = "clean-87"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c87" {
  bucket = aws_s3_bucket.c87.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c87.arn
    }
  }
}
resource "aws_kms_key" "c87" {
  description = "clean-87"
  enable_key_rotation = true
}
