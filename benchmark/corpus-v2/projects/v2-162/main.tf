

resource "aws_instance" "db" {
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

resource "aws_ebs_volume" "db1" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
  type              = "gp3"
}

resource "aws_ebs_volume" "db2" {
  availability_zone = "us-east-1b"
  size              = 20
  encrypted         = true
  type              = "gp3"
}
