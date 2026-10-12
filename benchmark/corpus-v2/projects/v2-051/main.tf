resource "aws_appstream_fleet" "designers" {
  name          = "designers"
  instance_type = "stream.standard.small"
  fleet_type    = "ON_DEMAND"
  image_name    = "AppStream-AmazonLinux2-09-21-2023"

  compute_capacity {
    desired_instances = 2
  }

  vpc_config {
    subnet_ids         = ["subnet-0a1b2c3d"]
    security_group_ids = ["sg-0a1b2c3d"]
  }

  enable_default_internet_access = true
}
