terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

resource "docker_image" "web" {
  name = "example/web:2.1.0"

  build {
    context = "."
  }
}

resource "docker_container" "web" {
  name  = "web"
  image = docker_image.web.image_id

  ports {
    internal = 3000
    external = 3000
  }

  restart = "unless-stopped"
}
