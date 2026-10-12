resource "aws_iam_policy" "v64" {
  name = "vuln-64"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow" Action = "iam:PassRole" Resource = "*" },
      { Effect = "Allow" Action = "ec2:RunInstances" Resource = "*" }
    ]
  })
}

