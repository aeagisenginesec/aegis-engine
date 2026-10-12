

resource "aws_instance" "app1" {
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

resource "aws_instance" "app2" {
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

resource "aws_lb" "app" {
  name                       = "app-alb"
  internal                   = true
  load_balancer_type         = "application"
  subnets                    = ["subnet-aaa", "subnet-bbb"]
  enable_deletion_protection = true
  drop_invalid_header_fields = true
  access_logs {
    bucket  = "app-alb-logs"
    enabled = true
  }
}
