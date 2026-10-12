resource "aws_lambda_permission" "open_invoke" {
  statement_id  = "OpenInvoke"
  action        = "lambda:InvokeFunction"
  function_name = "billing-hook"
  principal     = "*"
}
