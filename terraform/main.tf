resource "kubernetes_namespace" "sherlock" {
  metadata {
    name = var.namespace
  }
}

# Remaining resources (Secret, ConfigMap, PVC, Deployment, Service, Ingress, CronJob)
# follow once the app image exists.
