resource "aws_vpc" "demo" {
  cidr_block = "10.0.0.0/16"
}
resource "aws_subnet" "demo" {
  vpc_id     = aws_vpc.demo.id
  cidr_block = "10.0.1.0/24"
}
