resource "aws_lb" "vuln" {
  internal                   = true
  load_balancer_type         = "application"
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}
