resource "aws_transfer_server" "sftp" {
  endpoint_type        = "VPC"
  security_policy_name = "TransferSecurityPolicy-2018-11"
  logging_role         = "arn:aws:iam::123456789012:role/transfer-logging"
  endpoint_details {
    vpc_id             = "vpc-12345678"
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
}
