resource "aws_s3_bucket" "c145" {
  bucket = "clean-145"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c145" {
  bucket = aws_s3_bucket.c145.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c145.arn
    }
  }
}
resource "aws_kms_key" "c145" {
  description = "clean-145"
  enable_key_rotation = true
}
