resource "aws_appsync_graphql_api" "catalog" {
  name                = "catalog"
  authentication_type = "API_KEY"
  xray_enabled        = true

  log_config {
    cloudwatch_logs_role_arn = "arn:aws:iam::123456789012:role/appsync-logging"
    field_log_level          = "ERROR"
  }
}
