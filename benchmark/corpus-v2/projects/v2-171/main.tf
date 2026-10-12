

resource "aws_iam_role" "ci" {
  name = "ci-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "ci" {
  name = "ci-least-priv"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
    {
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = ["arn:aws:s3:::ci-artifacts/*"]
    }
    {
      Effect   = "Allow"
      Action   = ["ecr:BatchGetImage"]
      Resource = ["arn:aws:ecr:us-east-1:123456789012:repository/ci"]
    }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ci" {
  role       = aws_iam_role.ci.name
  policy_arn = aws_iam_policy.ci.arn
}
