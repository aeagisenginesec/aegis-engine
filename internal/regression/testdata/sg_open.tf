# Web-tier security group: SSH and RDP open to the world, plus unrestricted
# egress. Each overly-permissive rule should be a finding.
resource "aws_security_group" "web" {
  name        = "web-tier-sg"
  description = "Web tier - overly permissive"
  vpc_id      = "vpc-0a1b2c3d4e5f60718"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "unrestricted outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "prod"
  }
}
