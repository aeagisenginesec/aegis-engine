resource "aws_vpc" "demo" {
  cidr_block = "10.0.0.0/16"
}
resource "aws_subnet" "demo" {
  vpc_id     = aws_vpc.demo.id
  cidr_block = "10.0.1.0/24"
}
resource "aws_flow_log" "demo" {
  vpc_id               = aws_vpc.demo.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = "arn:aws:logs:us-east-1:123456789012:log-group:demo-flow-logs"
  iam_role_arn         = "arn:aws:iam::123456789012:role/demo-flow-log-role"
}
