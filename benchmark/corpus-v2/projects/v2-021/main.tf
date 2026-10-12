resource "aws_iam_role" "godmode" {
  name = "godmode"
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

resource "aws_iam_policy" "godmode" {
  name = "godmode"
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

resource "aws_iam_role_policy_attachment" "godmode" {
  role       = aws_iam_role.godmode.name
  policy_arn = aws_iam_policy.godmode.arn
}

resource "aws_iam_instance_profile" "godmode" {
  name = "godmode"
  role = aws_iam_role.godmode.name
}

resource "aws_instance" "legacy" {
  ami                = "ami-0a1b2c3d4e5f60718"
  instance_type      = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.godmode.name
  monitoring    = true
  metadata_options {
    http_tokens = "required"
  }
  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 30
    encrypted   = true
  }
}
