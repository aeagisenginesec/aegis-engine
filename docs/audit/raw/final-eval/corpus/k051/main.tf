terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

resource "docker_image" "app" {
  name = "example/app:latest"
}

resource "docker_container" "app" {
  name  = "app"
  image = docker_image.app.image_id

  privileged = true

  ports {
    internal = 8080
    external = 8080
  }

  volumes {
    host_path      = "/var/run/docker.sock"
    container_path = "/var/run/docker.sock"
  }

  env = [
    "DB_PASSWORD=s3cr3tP@ss",
    "API_KEY=ak_live_12345",
  ]

  restart = "always"
}
