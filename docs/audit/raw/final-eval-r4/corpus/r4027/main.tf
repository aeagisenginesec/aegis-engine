resource "aws_iam_user" "reader" {
  name = "reader-8fba47"
}

resource "aws_iam_user_policy" "reader" {
  user = aws_iam_user.reader.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::reports-8fba47",
       "arn:aws:s3:::reports-8fba47/*"]
    }]
  })
}

resource "aws_iam_user" "deployer" {
  name = "deployer-8fba47"
}

resource "aws_iam_user_policy" "deployer" {
  user = aws_iam_user.deployer.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "*"
      Resource = "*"
    }]
  })
}
