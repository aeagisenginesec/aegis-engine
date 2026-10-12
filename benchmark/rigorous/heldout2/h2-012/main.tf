resource "aws_dynamodb_table" "d12" {
  name = "heldout-12"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
