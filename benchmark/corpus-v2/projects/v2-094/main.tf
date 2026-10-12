resource "aws_sfn_state_machine" "etl" {
  name     = "etl"
  role_arn = "arn:aws:iam::123456789012:role/sfn"
  definition = <<JSON
{
  "StartAt": "Done",
  "States": {
    "Done": { "Type": "Pass", "End": true }
  }
}
JSON
}
