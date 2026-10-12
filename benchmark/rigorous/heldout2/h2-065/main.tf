resource "aws_dynamodb_table" "d65" {
  name = "heldout-65"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
