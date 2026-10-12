resource "aws_transfer_server" "sftp" {
  endpoint_type = "PUBLIC"
  logging_role  = "arn:aws:iam::123456789012:role/transfer-logging"
}
