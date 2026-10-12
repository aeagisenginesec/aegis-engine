resource "aws_lb" "storefront" {
  name               = "storefront"
  internal           = false
  load_balancer_type = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}
