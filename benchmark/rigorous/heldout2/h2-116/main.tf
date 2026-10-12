resource "aws_dynamodb_table" "d116" {
  name = "heldout-116"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
