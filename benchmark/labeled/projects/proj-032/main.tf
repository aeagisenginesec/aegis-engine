resource "aws_elb" "vuln" {
  name = "vuln"
  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "HTTP"
  }
  access_logs {
    bucket = "elb-logs-bucket"
  }
}
