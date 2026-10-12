resource "aws_dynamodb_table" "d33" {
  name = "heldout-33"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
