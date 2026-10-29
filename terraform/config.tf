# NVD API key, only used by the sync pods
resource "kubernetes_secret_v1" "nvd" {
  metadata {
    name      = "sherlock-nvd"
    namespace = kubernetes_namespace_v1.sherlock.metadata[0].name
    labels    = local.labels
  }

  data = {
    NVD_API_KEY = var.nvd_api_key
  }
}

# Inventory, mounted read-only to /config in the sync pods
resource "kubernetes_config_map_v1" "apps" {
  metadata {
    name      = "sherlock-apps"
    namespace = kubernetes_namespace_v1.sherlock.metadata[0].name
    labels    = local.labels
  }

  data = {
    "apps.yaml" = local.apps_yaml
  }
}
