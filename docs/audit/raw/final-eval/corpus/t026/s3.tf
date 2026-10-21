resource "aws_s3_bucket" "export" {
  bucket = "acme-snapshot-export-${var.bucket_suffix}"
  acl    = "public-read"

  tags = {
    Name = "snapshot-export"
  }
}

resource "aws_s3_bucket_policy" "export_open" {
  bucket = aws_s3_bucket.export.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicList"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:ListBucket", "s3:GetObject"]
        Resource = [
          aws_s3_bucket.export.arn,
          "${aws_s3_bucket.export.arn}/*"
        ]
      }
    ]
  })
}
