resource "aws_ec2_transit_gateway_route_table_propagation" "spread" {
  transit_gateway_attachment_id  = "tgw-attach-12345678"
  transit_gateway_route_table_id = "tgw-rtb-12345678"
}
