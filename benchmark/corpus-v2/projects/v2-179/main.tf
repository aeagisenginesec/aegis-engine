

resource "aws_kms_key" "app" {
  description             = "app data key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_key" "db" {
  description             = "db key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}
