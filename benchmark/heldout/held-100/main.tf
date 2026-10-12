resource "aws_kms_key" "v100" {
  description = "vuln-100"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v100" {
  function_name = "vuln-100"
  role = aws_iam_role.v100.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v100" {
  name = "vuln-100"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

resource "aws_instance" "v100" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecret123!"
    echo "starting app"
  EOF
}

