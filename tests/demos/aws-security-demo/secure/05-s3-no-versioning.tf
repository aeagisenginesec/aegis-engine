resource "aws_s3_bucket" "demo" {
  bucket = "demo-no-versioning-bucket"
  acl    = "private"
}
resource "aws_s3_bucket_versioning" "demo" {
  bucket = aws_s3_bucket.demo.id
  versioning_configuration {
    status = "Enabled"
  }
}
