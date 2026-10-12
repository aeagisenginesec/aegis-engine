variable "vpc_cidr" {
  type = string
  default = "10.0.0.0/16"
}

resource "aws_vpc" "mod" {
  cidr_block = var.vpc_cidr
  enable_dns_support = true
}
