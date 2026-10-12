


resource "aws_kms_key" "api_ecr" {
  description             = "ECR repository encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_ecr_repository" "api" {
  name                 = "api-repo"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.api_ecr.arn
  }
}


resource "aws_kms_key" "worker_ecr" {
  description             = "ECR repository encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_ecr_repository" "worker" {
  name                 = "worker-repo"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.worker_ecr.arn
  }
}
