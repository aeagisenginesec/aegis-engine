resource "aws_dynamodb_table" "d35" {
  name = "heldout-35"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
