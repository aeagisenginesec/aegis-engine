resource "aws_api_gateway_domain_name" "api" {
  domain_name     = "api.example.com"
  security_policy = "TLS_1_0"
}
