resource "aws_network_acl" "public" {
  vpc_id     = "vpc-0a1b2c3d"
  subnet_ids = ["subnet-0a1b2c3d"]

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}
