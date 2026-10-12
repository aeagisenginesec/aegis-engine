resource "aws_s3_bucket" "c104" {
  bucket = "clean-104"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c104" {
  bucket = aws_s3_bucket.c104.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c104.arn
    }
  }
}
resource "aws_kms_key" "c104" {
  description = "clean-104"
  enable_key_rotation = true
}
