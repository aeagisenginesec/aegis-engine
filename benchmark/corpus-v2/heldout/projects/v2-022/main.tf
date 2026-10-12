resource "aws_ram_resource_share" "subnets" {
  name                      = "shared-subnets"
  allow_external_principals = true
}
