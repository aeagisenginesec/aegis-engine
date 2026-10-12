resource "aws_dynamodb_table" "d30" {
  name = "heldout-30"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
