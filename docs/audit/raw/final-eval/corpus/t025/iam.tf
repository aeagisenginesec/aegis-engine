resource "aws_iam_role" "app" {
  name = "app-server-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "s3_scoped" {
  name = "app-s3-scoped"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::${var.app_bucket}",
          "arn:aws:s3:::${var.app_bucket}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "scoped" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.s3_scoped.arn
}

resource "aws_iam_policy" "admin_wildcard" {
  name = "app-admin-wildcard"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "wildcard" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.admin_wildcard.arn
}

resource "aws_iam_instance_profile" "app" {
  name = "app-server-profile"
  role = aws_iam_role.app.name
}
