resource "aws_instance" "v59" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecret123!"
    echo "starting app"
  EOF
}

resource "aws_ebs_volume" "v59" {
  availability_zone = "us-east-1a"
  size = 40
}

