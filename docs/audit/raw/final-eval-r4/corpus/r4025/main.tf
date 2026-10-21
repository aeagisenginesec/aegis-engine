resource "google_container_cluster" "main" {
  name = "main-32b6b4"
  location = "europe-west1"
  initial_node_count = 1
  master_authorized_networks_config {}
}

resource "aws_security_group" "bastion" {
  name = "bastion-32b6b4"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
