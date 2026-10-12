resource "aws_lb" "internal" {
  name                       = "internal"
  internal                   = true
  load_balancer_type         = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}
