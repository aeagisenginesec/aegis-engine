resource "aws_ssoadmin_permission_set" "superuser" {
  name         = "SuperUser"
  instance_arn = "arn:aws:sso:::instance/ssoins-0a1b2c3d4e5f60718"
}

resource "aws_ssoadmin_permission_set_inline_policy" "superuser_admin" {
  instance_arn       = "arn:aws:sso:::instance/ssoins-0a1b2c3d4e5f60718"
  permission_set_arn = aws_ssoadmin_permission_set.superuser.arn
  inline_policy      = <<POLICY
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
