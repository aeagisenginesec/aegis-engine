resource "aws_lb" "demo" {
  name               = "demo-plain-http"
  load_balancer_type = "application"
  subnets            = ["subnet-00000000", "subnet-11111111"]
}
resource "aws_lb_listener" "demo" {
  load_balancer_arn = aws_lb.demo.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/demo/0000000000000000"
  }
}
