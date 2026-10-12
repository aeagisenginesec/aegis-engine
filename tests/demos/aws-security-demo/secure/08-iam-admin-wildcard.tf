resource "aws_iam_policy" "demo" {
  name   = "demo-admin-wildcard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::demo-bucket", "arn:aws:s3:::demo-bucket/*"]
    }]
  })
}
