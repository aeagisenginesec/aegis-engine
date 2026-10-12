

resource "aws_lb" "web" {
  name                       = "web-alb"
  internal                   = true
  load_balancer_type         = "application"
  subnets                    = ["subnet-aaa", "subnet-bbb"]
  enable_deletion_protection = true
  drop_invalid_header_fields = true
  access_logs {
    bucket  = "web-alb-logs"
    enabled = true
  }
}

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
