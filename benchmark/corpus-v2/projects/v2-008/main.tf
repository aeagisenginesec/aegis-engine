resource "aws_iam_role" "ci_runner" {
  name                 = "ci-runner"
  max_session_duration = 72000
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}
