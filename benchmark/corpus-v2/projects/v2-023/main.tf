resource "aws_iam_role_policy" "starstar" {
  name = "starstar"
  role = "auditor"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*:*",
      "Resource": "*"
    }
  ]
}
POLICY
}
