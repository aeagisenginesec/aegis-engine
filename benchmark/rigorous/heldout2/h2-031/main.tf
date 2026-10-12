resource "aws_dynamodb_table" "d31" {
  name = "heldout-31"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
