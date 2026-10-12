resource "aws_athena_workgroup" "analytics" {
  name                            = "analytics"
  enforce_workgroup_configuration = false
  configuration {
    result_configuration {
      output_location = "s3://athena-results-bucket/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}
