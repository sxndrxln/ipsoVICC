# Regular NVD sync, Forbid prevents two runs at the same time
resource "kubernetes_cron_job_v1" "sync" {
  metadata {
    name      = "sherlock-sync"
    namespace = kubernetes_namespace_v1.sherlock.metadata[0].name
    labels    = local.sync_labels
  }

  spec {
    schedule                      = var.sync_schedule
    concurrency_policy            = "Forbid"
    starting_deadline_seconds     = 600
    successful_jobs_history_limit = 3
    failed_jobs_history_limit     = 3

    job_template {
      metadata {
        labels = local.sync_labels
      }

      spec {
        backoff_limit              = 1
        active_deadline_seconds    = 900
        ttl_seconds_after_finished = 86400

        template {
          metadata {
            labels = local.sync_labels
          }

          spec {
            restart_policy                  = "Never"
            automount_service_account_token = false
            enable_service_links            = false

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
              name              = "sync"
              image             = var.app_image
              image_pull_policy = "IfNotPresent"
              command           = ["python", "-m", "sherlock.sync"]

              env {
                name = "NVD_API_KEY"

                value_from {
                  secret_key_ref {
                    name = kubernetes_secret_v1.nvd.metadata[0].name
                    key  = "NVD_API_KEY"
                  }
                }
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

              volume_mount {
                name       = "data"
                mount_path = "/data"
              }

              volume_mount {
                name       = "config"
                mount_path = "/config"
                read_only  = true
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
              name = "config"

              config_map {
                name = kubernetes_config_map_v1.apps.metadata[0].name
              }
            }

            volume {
              name = "tmp"

              empty_dir {
                size_limit = "16Mi"
              }
            }
          }
        }
      }
    }
  }
}

# One-off sync on apply. The job name contains the hash of apps.yaml,
# so a changed inventory creates a new job and is synced right away.
resource "kubernetes_job_v1" "sync_now" {
  metadata {
    name      = "sherlock-sync-${local.apps_yaml_hash}"
    namespace = kubernetes_namespace_v1.sherlock.metadata[0].name
    labels    = local.sync_labels
  }

  spec {
    backoff_limit           = 1
    active_deadline_seconds = 900

    template {
      metadata {
        labels = local.sync_labels
      }

      spec {
        restart_policy                  = "Never"
        automount_service_account_token = false
        enable_service_links            = false

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
          name              = "sync"
          image             = var.app_image
          image_pull_policy = "IfNotPresent"
          command           = ["python", "-m", "sherlock.sync"]

          env {
            name = "NVD_API_KEY"

            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.nvd.metadata[0].name
                key  = "NVD_API_KEY"
              }
            }
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

          volume_mount {
            name       = "data"
            mount_path = "/data"
          }

          volume_mount {
            name       = "config"
            mount_path = "/config"
            read_only  = true
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
          name = "config"

          config_map {
            name = kubernetes_config_map_v1.apps.metadata[0].name
          }
        }

        volume {
          name = "tmp"

          empty_dir {
            size_limit = "16Mi"
          }
        }
      }
    }
  }

  wait_for_completion = true

  timeouts {
    create = "15m"
  }
}
