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

resource "kubernetes_deployment" "agent" {
  metadata {
    name = "host-agent"
    labels = {
      app = "host-agent"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "host-agent"
      }
    }

    template {
      metadata {
        labels = {
          app = "host-agent"
        }
      }

      spec {
        host_network = true

        container {
          name  = "agent"
          image = "example/host-agent:1.0"

          security_context {
            privileged = true
          }

          volume_mount {
            name       = "rootfs"
            mount_path = "/host"
          }
        }

        volume {
          name = "rootfs"

          host_path {
            path = "/"
          }
        }
      }
    }
  }
}

resource "kubernetes_cluster_role_binding" "agent_admin" {
  metadata {
    name = "host-agent-admin"
  }

  subject {
    kind      = "ServiceAccount"
    name      = "default"
    namespace = "default"
  }

  role_ref {
    kind      = "ClusterRole"
    name      = "cluster-admin"
    api_group = "rbac.authorization.k8s.io"
  }
}
