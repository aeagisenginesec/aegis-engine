resource "aws_dms_replication_instance" "migration" {
  replication_instance_id  = "migration"
  replication_instance_class = "dms.t3.micro"
  allocated_storage          = 50
  publicly_accessible        = true
}
