resource "aws_appstream_fleet" "office" {
  name          = "office"
  instance_type = "stream.standard.small"
  fleet_type    = "ON_DEMAND"
  compute_capacity {
    desired_instances = 1
  }
  enable_default_internet_access = true
}
