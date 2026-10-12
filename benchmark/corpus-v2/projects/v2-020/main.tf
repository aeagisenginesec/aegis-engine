resource "aws_iam_group" "contractors" {
  name = "contractors"
}

resource "aws_iam_group_policy" "contractor_power" {
  name  = "contractor-power"
  group = aws_iam_group.contractors.name
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ScopedRead",
      "Effect": "Allow",
      "Action": ["ec2:DescribeInstances", "s3:ListBucket"],
      "Resource": "*"
    },
    {
      "Sid": "LegacyAdmin",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}
