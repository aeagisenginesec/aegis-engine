resource "aws_iam_role" "etl_worker" {
  name = "etl-worker"
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

resource "aws_iam_policy" "etl_data" {
  name = "etl-data"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*", "iam:PassRole"],
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "etl_attach" {
  role       = aws_iam_role.etl_worker.name
  policy_arn = aws_iam_policy.etl_data.arn
}

resource "aws_iam_instance_profile" "etl_worker" {
  name = "etl-worker"
  role = aws_iam_role.etl_worker.name
}

resource "aws_instance" "etl" {
  ami                = "ami-0a1b2c3d4e5f60718"
  instance_type      = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.etl_worker.name
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
