resource "aws_glue_job" "etl" {
  name     = "etl"
  role_arn = "arn:aws:iam::123456789012:role/glue"
  command {
    script_location = "s3://etl-scripts-bucket/job.py"
  }
}
