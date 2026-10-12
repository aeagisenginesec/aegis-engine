resource "aws_s3_bucket" "c138" {
  bucket = "clean-138"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c138" {
  bucket = aws_s3_bucket.c138.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c138.arn
    }
  }
}
resource "aws_kms_key" "c138" {
  description = "clean-138"
  enable_key_rotation = true
}
