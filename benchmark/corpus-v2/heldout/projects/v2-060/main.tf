resource "aws_ecr_repository" "ledger" {
  name                 = "ledger-images"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}
