resource "aws_dynamodb_table" "vuln" {
  name         = "vuln"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc"
  }
  point_in_time_recovery {
    enabled = true
  }
  deletion_protection_enabled = true
}
