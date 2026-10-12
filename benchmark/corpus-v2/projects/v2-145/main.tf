

resource "aws_efs_file_system" "shared" {
  encrypted = true
}


resource "aws_kms_key" "shared_bv" {
  description             = "Backup vault encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_backup_vault" "shared" {
  name        = "shared-vault"
  kms_key_arn = aws_kms_key.shared_bv.arn
}
