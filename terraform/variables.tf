# Values without default (image, API key) are set in terraform.tfvars
variable "kubeconfig_path" {
  description = "Path to the kubeconfig fetched from the k3s node"
  type        = string
  default     = "../kubeconfig/srv-k8s01.yaml"
}

variable "namespace" {
  description = "Kubernetes namespace for all app resources"
  type        = string
  default     = "sherlock"
}

variable "app_image" {
  description = "Container image of the app on Docker Hub, pinned by digest"
  type        = string
}

variable "app_host" {
  description = "Public hostname the ingress listens on"
  type        = string
  default     = "sherlock.beste.host"
}

variable "apps_file" {
  description = "Demo application inventory, mounted into the pods as ConfigMap"
  type        = string
  default     = "../data/apps.yaml"
}

variable "sync_schedule" {
  description = "Cron schedule of the vulnerability sync job"
  type        = string
  default     = "0 */6 * * *"
}

variable "nvd_api_key" {
  description = "NVD API key (https://nvd.nist.gov/developers/request-an-api-key)"
  type        = string
  sensitive   = true
}

variable "data_size" {
  description = "Size of the persistent volume for the SQLite database"
  type        = string
  default     = "1Gi"
}
