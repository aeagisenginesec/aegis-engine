

resource "aws_sqs_queue" "tasks" {
  name                    = "tasks-queue"
  sqs_managed_sse_enabled = true
}

resource "aws_instance" "worker" {
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

resource "aws_iam_role" "qw" {
  name = "qw-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "qw" {
  name = "qw-least-priv"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
    {
      Effect   = "Allow"
      Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage"]
      Resource = ["arn:aws:sqs:us-east-1:123456789012:tasks"]
    }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "qw" {
  role       = aws_iam_role.qw.name
  policy_arn = aws_iam_policy.qw.arn
}
