

resource "aws_dynamodb_table" "sessions" {
  name         = "sessions-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  server_side_encryption {
    enabled = true
  }
  point_in_time_recovery {
    enabled = true
  }
  deletion_protection_enabled = true
}
