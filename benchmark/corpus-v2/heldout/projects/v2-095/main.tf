resource "aws_transfer_server" "sftp" {
  endpoint_type = "VPC"
  endpoint_details {
    vpc_id             = "vpc-12345678"
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
}
