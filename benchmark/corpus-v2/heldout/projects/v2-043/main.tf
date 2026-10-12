resource "aws_lb" "internal" {
  name               = "internal"
  internal           = true
  load_balancer_type = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}

resource "aws_lb_target_group" "api" {
  name     = "api"
  port     = 80
  protocol = "HTTP"
  vpc_id   = "vpc-0a1b2c3d"
}
