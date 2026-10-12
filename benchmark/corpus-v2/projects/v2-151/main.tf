

resource "aws_dynamodb_table" "orders" {
  name         = "orders-table"
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

resource "aws_sqs_queue" "orders" {
  name                    = "orders-queue"
  sqs_managed_sse_enabled = true
}
