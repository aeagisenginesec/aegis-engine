resource "aws_codepipeline_webhook" "deploy" {
  name            = "deploy"
  target_pipeline = "webapp"
  target_action   = "Source"
  authentication  = "UNAUTHENTICATED"

  filter {
    json_path    = "$.ref"
    match_equals = "refs/heads/main"
  }
}
