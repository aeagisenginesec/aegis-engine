resource "aws_iam_user" "operator" {
  name = "operator"
}

resource "aws_iam_user_policy" "operator_admin" {
  name = "operator-admin"
  user = aws_iam_user.operator.name
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
