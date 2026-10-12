resource "aws_vpc_endpoint" "dynamo" {
  vpc_id            = "vpc-0a1b2c3d"
  service_name      = "com.amazonaws.us-east-1.dynamodb"
  vpc_endpoint_type = "Gateway"
}
