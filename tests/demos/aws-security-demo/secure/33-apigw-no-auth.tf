resource "aws_api_gateway_rest_api" "demo" {
  name = "demo-api"
}
resource "aws_api_gateway_resource" "demo" {
  rest_api_id = aws_api_gateway_rest_api.demo.id
  parent_id   = aws_api_gateway_rest_api.demo.root_resource_id
  path_part   = "items"
}
resource "aws_api_gateway_method" "demo" {
  rest_api_id   = aws_api_gateway_rest_api.demo.id
  resource_id   = aws_api_gateway_resource.demo.id
  http_method   = "GET"
  authorization = "AWS_IAM"
}
