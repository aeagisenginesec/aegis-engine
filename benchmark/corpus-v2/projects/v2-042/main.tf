resource "aws_network_acl" "dmz" {
  vpc_id     = "vpc-0a1b2c3d"
  subnet_ids = ["subnet-0a1b2c3d"]
}

resource "aws_network_acl_rule" "dmz_in" {
  network_acl_id = aws_network_acl.dmz.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}
