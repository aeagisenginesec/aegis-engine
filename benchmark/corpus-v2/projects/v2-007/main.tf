resource "aws_iam_policy" "almost_all" {
  name = "almost-all"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "NotAction": ["iam:DeleteAccountPasswordPolicy"],
      "Resource": "*"
    }
  ]
}
POLICY
}
