terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

resource "docker_image" "svc" {
  name = "example/svc:1.3.0"

  build {
    context = "."
  }
}

resource "docker_container" "svc" {
  name     = "svc"
  image    = docker_image.svc.image_id
  user     = "65532"
  readonly = true

  ports {
    internal = 8080
    external = 8080
  }

  healthcheck {
    test     = ["CMD", "/svc", "--healthcheck"]
    interval = "30s"
    timeout  = "5s"
    retries  = 3
  }

  restart = "unless-stopped"
}
