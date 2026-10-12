

resource "aws_instance" "bastion" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  monitoring    = true
  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    encrypted = true
  }
  ebs_optimized = true
}

resource "aws_iam_role" "bastion" {
  name = "bastion-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "bastion" {
  name = "bastion-least-priv"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
    {
      Effect   = "Allow"
      Action   = ["ssm:StartSession"]
      Resource = ["arn:aws:ec2:us-east-1:123456789012:instance/*"]
    }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bastion" {
  role       = aws_iam_role.bastion.name
  policy_arn = aws_iam_policy.bastion.arn
}
