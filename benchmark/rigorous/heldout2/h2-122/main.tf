resource "aws_dynamodb_table" "d122" {
  name = "heldout-122"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
