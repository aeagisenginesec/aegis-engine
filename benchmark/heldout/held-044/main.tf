resource "aws_iam_policy" "v44" {
  name = "vuln-44"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow" Action = "iam:PassRole" Resource = "*" },
      { Effect = "Allow" Action = "ec2:RunInstances" Resource = "*" }
    ]
  })
}

