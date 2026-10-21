resource "google_storage_bucket" "data" {
  name = "data-62da99"
  location = "EU"
  uniform_bucket_level_access = true
}

resource "aws_instance" "web" {
  ami = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
    http_endpoint = "enabled"
  }
  tags = { Name = "web-62da99" }
}
