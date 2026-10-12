resource "aws_vpc_endpoint" "s3" {
  vpc_id       = "vpc-12345678"
  service_name = "com.amazonaws.us-east-1.s3"
}
