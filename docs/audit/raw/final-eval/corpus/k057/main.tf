terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

variable "api_token" {
  type      = string
  sensitive = true
}

resource "docker_image" "svc" {
  name = "example/svc:1.3.0"

  build {
    context = "."
    build_args = {
      API_TOKEN = var.api_token
    }
  }
}

resource "docker_container" "svc" {
  name  = "svc"
  image = docker_image.svc.image_id
  user  = "10001"

  ports {
    internal = 8080
    external = 8080
  }

  restart = "unless-stopped"
}
