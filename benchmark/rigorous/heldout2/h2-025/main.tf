resource "aws_dynamodb_table" "d25" {
  name = "heldout-25"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
