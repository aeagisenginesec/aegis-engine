resource "aws_dynamodb_table" "d40" {
  name = "heldout-40"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
