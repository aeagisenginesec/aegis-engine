resource "aws_s3_bucket" "c63" {
  bucket = "clean-63"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c63" {
  bucket = aws_s3_bucket.c63.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c63.arn
    }
  }
}
resource "aws_kms_key" "c63" {
  description = "clean-63"
  enable_key_rotation = true
}
