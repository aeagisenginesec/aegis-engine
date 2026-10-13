terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

resource "aws_launch_template" "web" {
  name          = "web-lt"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.small"

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = ["sg-web01"]
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size = 30
      volume_type = "gp3"
      encrypted   = true
    }
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "web-asg-instance"
    }
  }
}

resource "aws_lb_target_group" "web" {
  name     = "web-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = "vpc-6f7a8b9c0d1e23546"

  health_check {
    path     = "/health"
    protocol = "HTTP"
    matcher  = "200"
  }

  tags = {
    Name = "web-tg"
  }
}

resource "aws_lb" "web" {
  name               = "web-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["sg-alb02"]
  subnets            = ["subnet-pub1", "subnet-pub2"]

  tags = {
    Name = "web-alb"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

resource "aws_autoscaling_group" "web" {
  name                = "web-asg"
  min_size            = 2
  max_size            = 6
  desired_capacity    = 3
  vpc_zone_identifier = ["subnet-pub1", "subnet-pub2"]
  target_group_arns   = [aws_lb_target_group.web.arn]

  launch_template {
    id      = aws_launch_template.web.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "web-asg"
    propagate_at_launch = true
  }
}
