resource "aws_iam_user" "deployer" {
  name = "deployer-852c2d"
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

resource "aws_iam_user" "ops" {
  name = "ops-852c2d"
}

resource "aws_iam_user_policy_attachment" "ops" {
  user = aws_iam_user.ops.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
