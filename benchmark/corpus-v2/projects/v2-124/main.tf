resource "aws_dms_replication_instance" "mig" {
  replication_instance_id    = "mig"
  replication_instance_class = "dms.t3.micro"
  allocated_storage          = 50
  publicly_accessible        = true
}
