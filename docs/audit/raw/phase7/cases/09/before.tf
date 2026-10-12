resource "aws_s3_bucket" "demo" {
  bucket = "demo-public-policy-bucket"
}
resource "aws_s3_bucket_policy" "demo" {
  bucket = aws_s3_bucket.demo.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::demo-public-policy-bucket/*"
    }]
  })
}
