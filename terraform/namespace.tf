# Own namespace for all resources of the app
resource "kubernetes_namespace_v1" "sherlock" {
  metadata {
    name   = var.namespace
    labels = local.labels
  }
}
