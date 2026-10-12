resource "aws_iam_policy" "v122" {
  name = "vuln-122"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow" Action = "iam:PassRole" Resource = "*" },
      { Effect = "Allow" Action = "ec2:RunInstances" Resource = "*" }
    ]
  })
}

resource "aws_instance" "v122" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecret123!"
    echo "starting app"
  EOF
}

