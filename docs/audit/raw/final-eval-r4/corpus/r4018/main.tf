resource "aws_security_group" "app" {
  name = "app-bdc155"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["203.0.113.238/32"]
  }
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_user" "reader" {
  name = "reader-bdc155"
}

resource "aws_iam_user_policy" "reader" {
  user = aws_iam_user.reader.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::reports-bdc155",
       "arn:aws:s3:::reports-bdc155/*"]
    }]
  })
}
