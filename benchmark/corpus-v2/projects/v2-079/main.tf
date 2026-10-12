resource "aws_codebuild_project" "build" {
  name         = "build"
  service_role = "arn:aws:iam::123456789012:role/codebuild"
  artifacts {
    type                = "S3"
    location            = "build-artifacts-bucket"
    encryption_disabled = true
  }
  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"
  }
  source {
    type     = "GITHUB"
    location = "https://github.com/example/app"
  }
  logs_config {
    cloudwatch_logs {
      status = "ENABLED"
    }
  }
}
