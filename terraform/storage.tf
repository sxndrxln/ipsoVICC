# SQLite database. k3s local-path stores it on the data disk of the VM (/opt).
resource "kubernetes_persistent_volume_claim_v1" "data" {
  metadata {
    name      = "sherlock-data"
    namespace = kubernetes_namespace_v1.sherlock.metadata[0].name
    labels    = local.labels
  }

  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = "local-path"

    resources {
      requests = {
        storage = var.data_size
      }
    }
  }

  # local-path only binds once a pod uses the volume
  wait_until_bound = false
}
