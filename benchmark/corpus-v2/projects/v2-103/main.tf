resource "aws_neptune_cluster" "graph" {
  cluster_identifier                = "graph"
  engine                            = "neptune"
  storage_encrypted                 = true
  backup_retention_period           = 7
  deletion_protection               = true
  iam_database_authentication_enabled = true
}
