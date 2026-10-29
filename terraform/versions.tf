terraform {
  required_version = ">= 1.6"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.4"
    }
  }
}

# Uses the kubeconfig fetched by the Ansible k3s role
provider "kubernetes" {
  config_path = var.kubeconfig_path
}
