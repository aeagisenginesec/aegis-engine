variable "bucket_name" {}

resource "aws_s3_bucket" "data" {
  bucket = var.bucket_name

  tags = {
    Ami = data.aws_ami.x.id
  }
}
