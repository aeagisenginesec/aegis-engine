


resource "aws_kms_key" "frontend_ecr" {
  description             = "ECR repository encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_ecr_repository" "frontend" {
  name                 = "frontend-repo"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.frontend_ecr.arn
  }
}
