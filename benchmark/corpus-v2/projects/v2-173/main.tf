

resource "aws_iam_role" "ro" {
  name = "ro-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "ro" {
  name = "ro-least-priv"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
    {
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::shared-docs/*"]
    }
    {
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem", "dynamodb:Scan"]
      Resource = ["arn:aws:dynamodb:us-east-1:123456789012:table/ref"]
    }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ro" {
  role       = aws_iam_role.ro.name
  policy_arn = aws_iam_policy.ro.arn
}
