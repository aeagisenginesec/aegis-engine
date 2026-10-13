terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

resource "docker_image" "api" {
  name = "example/api:3.0.0"

  build {
    context = "."
  }
}

resource "docker_container" "api" {
  name  = "api"
  image = docker_image.api.image_id

  ports {
    internal = 8000
    external = 8000
  }

  restart = "unless-stopped"
}
