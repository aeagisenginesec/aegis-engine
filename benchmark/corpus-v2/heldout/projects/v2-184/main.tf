


resource "aws_kms_key" "daily_bv" {
  description             = "Backup vault encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_backup_vault" "daily" {
  name        = "daily-vault"
  kms_key_arn = aws_kms_key.daily_bv.arn
}

resource "aws_ebs_volume" "src" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
  type              = "gp3"
}
