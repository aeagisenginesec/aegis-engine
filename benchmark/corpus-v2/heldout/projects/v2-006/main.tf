resource "aws_iam_role" "jump_host" {
  name = "jump-host"
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

resource "aws_iam_policy" "hop" {
  name = "hop"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["sts:AssumeRole"],
      "Resource": "arn:aws:iam::123456789012:role/*"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "hop_attach" {
  role       = aws_iam_role.jump_host.name
  policy_arn = aws_iam_policy.hop.arn
}

resource "aws_iam_instance_profile" "jump_host" {
  name = "jump-host"
  role = aws_iam_role.jump_host.name
}

resource "aws_instance" "bastion" {
  ami                = "ami-0a1b2c3d4e5f60718"
  instance_type      = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.jump_host.name
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
