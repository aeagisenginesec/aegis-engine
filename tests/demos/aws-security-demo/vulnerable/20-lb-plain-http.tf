resource "aws_lb" "demo" {
  name               = "demo-plain-http"
  load_balancer_type = "application"
  subnets            = ["subnet-00000000", "subnet-11111111"]
}
resource "aws_lb_listener" "demo" {
  load_balancer_arn = aws_lb.demo.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/demo/0000000000000000"
  }
}
