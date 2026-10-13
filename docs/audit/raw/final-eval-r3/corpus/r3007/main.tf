resource "azurerm_network_security_group" "web" {
  name = "web-201532"
  location = "westeurope"
  resource_group_name = "rg-web"
  security_rule {
    name = "ssh"
    priority = 100
    direction = "Inbound"
    access = "Allow"
    protocol = "Tcp"
    source_port_range = "*"
    destination_port_range = "22"
    source_address_prefix = "*"
    destination_address_prefix = "*"
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "data-lake-201532"
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = "*"
      Action = "s3:GetObject"
      Resource = "arn:aws:s3:::data-lake-201532/*"
    }]
  })
}
