resource "aws_s3_bucket" "c75" {
  bucket = "clean-75"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c75" {
  bucket = aws_s3_bucket.c75.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c75.arn
    }
  }
}
resource "aws_kms_key" "c75" {
  description = "clean-75"
  enable_key_rotation = true
}
