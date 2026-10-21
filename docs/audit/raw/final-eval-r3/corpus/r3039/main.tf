resource "google_compute_instance" "nat" {
  name = "nat-26195a"
  machine_type = "e2-medium"
  zone = "europe-west1-b"
  can_ip_forward = true
  boot_disk {
    initialize_params { image = "debian-cloud/debian-12" }
  }
  network_interface { network = "default"
    access_config {}
  }
}

resource "aws_iam_user" "reader" {
  name = "reader-26195a"
}

resource "aws_iam_user_policy" "reader" {
  user = aws_iam_user.reader.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::reports-26195a",
       "arn:aws:s3:::reports-26195a/*"]
    }]
  })
}

resource "aws_security_group" "app" {
  name = "app-26195a"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["203.0.113.4/32"]
  }
  ingress {
    from_port = 443
    to_port = 443
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
