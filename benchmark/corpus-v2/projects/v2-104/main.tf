resource "aws_docdb_cluster" "ledger" {
  cluster_identifier      = "ledger"
  engine                  = "docdb"
  master_username         = "admin"
  storage_encrypted       = true
  backup_retention_period = 7
  deletion_protection     = true
}
