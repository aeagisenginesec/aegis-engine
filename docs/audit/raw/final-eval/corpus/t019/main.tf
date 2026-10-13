terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "alb_logs" {
  bucket = "acme-alb-logs-eu-9c2d"

  tags = {
    Name = "alb-logs"
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::156460612806:root" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.alb_logs.arn}/*"
      }
    ]
  })
}

resource "aws_lb" "web" {
  name                       = "web-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = ["sg-alb01"]
  subnets                    = ["subnet-pub1", "subnet-pub2"]
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    enabled = true
  }

  tags = {
    Name = "web-alb"
  }
}

resource "aws_lb_target_group" "web" {
  name     = "web-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = "vpc-4d5e6f7a8b9c01324"

  health_check {
    path     = "/health"
    protocol = "HTTPS"
    matcher  = "200"
  }

  tags = {
    Name = "web-tg"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.web.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:eu-west-1:123456789012:certificate/a1b2c3d4-5678-90ab-cdef-1234567890ab"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.web.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_wafv2_web_acl_association" "web" {
  resource_arn = aws_lb.web.arn
  web_acl_arn  = "arn:aws:wafv2:eu-west-1:123456789012:regional/webacl/web-protection/a1b2c3d4"
}
