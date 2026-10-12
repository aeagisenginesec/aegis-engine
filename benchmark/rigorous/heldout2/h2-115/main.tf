resource "aws_dynamodb_table" "d115" {
  name = "heldout-115"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
