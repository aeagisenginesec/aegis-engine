resource "aws_dynamodb_table" "d43" {
  name = "heldout-43"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
