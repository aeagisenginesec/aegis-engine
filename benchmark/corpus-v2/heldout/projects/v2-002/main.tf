resource "aws_iam_group" "platform" {
  name = "platform"
}

resource "aws_iam_group_policy" "platform_admin" {
  name  = "platform-admin"
  group = aws_iam_group.platform.name
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}
