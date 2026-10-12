resource "aws_vpc_endpoint_service" "privatelink" {
  acceptance_required        = false
  network_load_balancer_arns = ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/x/abcd"]
}
