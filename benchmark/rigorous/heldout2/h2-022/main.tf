resource "aws_dynamodb_table" "d22" {
  name = "heldout-22"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
