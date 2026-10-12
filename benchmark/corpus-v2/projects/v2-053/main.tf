resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = "vpc-0a1b2c3d"
  service_name        = "com.amazonaws.us-east-1.ecr.api"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "ecr:*",
      "Resource": "*"
    }
  ]
}
POLICY
}
