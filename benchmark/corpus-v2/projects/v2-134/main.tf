
resource "aws_db_instance" "dbs" {
  for_each                    = toset(["one", "two"])
  identifier                  = "db-${each.key}"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  manage_master_user_password = true
}
