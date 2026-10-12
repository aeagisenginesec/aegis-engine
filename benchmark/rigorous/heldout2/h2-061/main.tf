resource "aws_dynamodb_table" "d61" {
  name = "heldout-61"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
