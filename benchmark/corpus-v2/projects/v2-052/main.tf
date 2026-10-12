resource "aws_vpc_endpoint_service" "partner_api" {
  acceptance_required        = false
  network_load_balancer_arns = ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/partner/0a1b2c3d4e5f6071"]
}
