resource "aws_subnet" "vuln" {
  vpc_id                  = "vpc-12345678"
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}
