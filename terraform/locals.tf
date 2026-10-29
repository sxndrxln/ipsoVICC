locals {
  # Common labels, web and sync pods differ in the component label
  labels = {
    "app.kubernetes.io/name"       = "sherlock"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  web_labels  = merge(local.labels, { "app.kubernetes.io/component" = "web" })
  sync_labels = merge(local.labels, { "app.kubernetes.io/component" = "sync" })

  # Short hash of apps.yaml, part of the name of the one-off sync job
  apps_yaml      = file(var.apps_file)
  apps_yaml_hash = substr(sha256(local.apps_yaml), 0, 8)

  # User of the container image (see Dockerfile)
  uid = 10001
}
