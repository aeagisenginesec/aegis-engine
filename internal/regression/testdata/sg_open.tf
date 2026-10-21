# Web-tier security group: SSH and RDP open to the world, plus unrestricted
# egress. Each overly-permissive rule should be a finding. The instance
# below attaches the group, so the egress rule carries traffic and 005
# fires; a standalone group would stay quiet for egress (attachment
# gate — see TestSGEgress_CheckAllStandaloneQuiet).
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

resource "aws_instance" "web" {
  ami                    = "ami-0123456789abcdef0"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web.id]
}
