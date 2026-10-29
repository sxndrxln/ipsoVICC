# Web UI and API. Single replica because SQLite lies on a ReadWriteOnce volume.
resource "kubernetes_deployment_v1" "web" {
  metadata {
    name      = "sherlock-web"
    namespace = kubernetes_namespace_v1.sherlock.metadata[0].name
    labels    = local.web_labels
  }

  spec {
    replicas = 1

    # Stop the old pod first so the new one can mount the volume
    strategy {
      type = "Recreate"
    }

    selector {
      match_labels = local.web_labels
    }

    template {
      metadata {
        labels = local.web_labels
      }

      spec {
        automount_service_account_token = false
        enable_service_links            = false

        # Non-root, read-only root filesystem, no capabilities
        security_context {
          run_as_non_root = true
          run_as_user     = local.uid
          run_as_group    = local.uid
          fs_group        = local.uid

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "web"
          image             = var.app_image
          image_pull_policy = "IfNotPresent"

          port {
            name           = "http"
            container_port = 8000
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true

            capabilities {
              drop = ["ALL"]
            }
          }

          resources {
            requests = {
              cpu    = "50m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "256Mi"
            }
          }

          # Both probes check /healthz incl. database access
          readiness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            period_seconds = 10
          }

          liveness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            initial_delay_seconds = 10
            period_seconds        = 30
          }

          volume_mount {
            name       = "data"
            mount_path = "/data"
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }

        volume {
          name = "data"

          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.data.metadata[0].name
          }
        }

        volume {
          # Writable /tmp, the root filesystem is read-only
          name = "tmp"

          empty_dir {
            size_limit = "16Mi"
          }
        }
      }
    }
  }
}

# Cluster-internal service for the ingress
resource "kubernetes_service_v1" "web" {
  metadata {
    name      = "sherlock-web"
    namespace = kubernetes_namespace_v1.sherlock.metadata[0].name
    labels    = local.web_labels
  }

  spec {
    type     = "ClusterIP"
    selector = local.web_labels

    port {
      name        = "http"
      port        = 80
      target_port = "http"
    }
  }
}

# Traefik (part of k3s) routes the hostname to the service.
# TLS ends at the reverse proxy in front of the VM.
resource "kubernetes_ingress_v1" "web" {
  metadata {
    name      = "sherlock-web"
    namespace = kubernetes_namespace_v1.sherlock.metadata[0].name
    labels    = local.web_labels
  }

  spec {
    ingress_class_name = "traefik"

    rule {
      host = var.app_host

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = kubernetes_service_v1.web.metadata[0].name

              port {
                name = "http"
              }
            }
          }
        }
      }
    }
  }
}
