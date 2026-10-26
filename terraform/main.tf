resource "kubernetes_namespace" "sherlock" {
  metadata {
    name = var.namespace
  }
}
