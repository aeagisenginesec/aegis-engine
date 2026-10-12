resource "aws_lb" "vuln" {
  name                       = "vuln"
  internal                   = true
  load_balancer_type         = "application"
  drop_invalid_header_fields = false
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}
