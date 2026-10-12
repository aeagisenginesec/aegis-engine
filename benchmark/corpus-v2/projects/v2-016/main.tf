resource "aws_apigatewayv2_route" "events" {
  api_id             = "a1b2c3d4e5"
  route_key          = "POST /events"
  authorization_type = "NONE"
  target             = "integrations/abc123"
}
