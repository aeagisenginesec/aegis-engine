resource "aws_dynamodb_table" "d117" {
  name = "heldout-117"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
