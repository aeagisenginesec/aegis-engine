resource "aws_dynamodb_table" "d121" {
  name = "heldout-121"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
