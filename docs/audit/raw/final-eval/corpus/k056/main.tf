terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
  }
}

provider "kubernetes" {
  config_path = "~/.kube/config"
}

# Terraform-managed copy of deployment.yaml
resource "kubernetes_deployment" "cache" {
  metadata {
    name = "cache"
    labels = {
      app = "cache"
    }
  }

  spec {
    replicas = 2

    selector {
      match_labels = {
        app = "cache"
      }
    }

    template {
      metadata {
        labels = {
          app = "cache"
        }
      }

      spec {
        container {
          name  = "cache"
          image = "example/cache:4.0.1"

          security_context {
            privileged = true
          }

          resources {
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }
        }
      }
    }
  }
}
