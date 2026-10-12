resource "aws_iam_policy" "vuln" {
  name   = "vuln"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:CreatePolicy", "iam:AttachRolePolicy"],
      "Resource": "*"
    }
  ]
}
POLICY
}
