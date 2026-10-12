

resource "aws_instance" "web" {
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

resource "aws_ebs_volume" "web_data" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
  type              = "gp3"
}
