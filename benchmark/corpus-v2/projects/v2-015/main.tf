resource "aws_api_gateway_method" "orders_post" {
  rest_api_id   = "a1b2c3d4e5"
  resource_id   = "f6g7h8i9j0"
  http_method   = "POST"
  authorization = "NONE"
}
