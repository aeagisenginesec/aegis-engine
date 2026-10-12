resource "aws_ecr_repository" "demo" {
  name = "demo-repo"
  image_scanning_configuration {
    scan_on_push = true
  }
}
