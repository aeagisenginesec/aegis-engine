resource "aws_dynamodb_table" "d126" {
  name = "heldout-126"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
