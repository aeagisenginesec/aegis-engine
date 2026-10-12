resource "aws_codepipeline" "deploy" {
  name     = "deploy"
  role_arn = "arn:aws:iam::123456789012:role/codepipeline"
  artifact_store {
    location = "deploy-artifacts-bucket"
    type     = "S3"
  }
  stage {
    name = "Source"
    action {
      name             = "Source"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      output_artifacts = ["src"]
    }
  }
}
