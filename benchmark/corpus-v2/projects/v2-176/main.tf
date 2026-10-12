

resource "aws_iam_role" "svc" {
  name = "svc-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "svca" {
  name = "svca-least-priv"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
    {
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::cfg-bucket/*"]
    }
    ]
  })
}

resource "aws_iam_policy" "svcb" {
  name = "svcb-least-priv"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
    {
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = ["arn:aws:secretsmanager:us-east-1:123456789012:secret:app-*"]
    }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "svca" {
  role       = aws_iam_role.svc.name
  policy_arn = aws_iam_policy.svca.arn
}

resource "aws_iam_role_policy_attachment" "svcb" {
  role       = aws_iam_role.svc.name
  policy_arn = aws_iam_policy.svcb.arn
}
