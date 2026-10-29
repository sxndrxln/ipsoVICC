# Block all traffic in the namespace, the policies below allow only what is needed
resource "kubernetes_network_policy_v1" "default_deny" {
  metadata {
    name      = "default-deny"
    namespace = kubernetes_namespace_v1.sherlock.metadata[0].name
    labels    = local.labels
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

# Web pod: only reachable from Traefik on port 8000
resource "kubernetes_network_policy_v1" "web_from_traefik" {
  metadata {
    name      = "web-from-traefik"
    namespace = kubernetes_namespace_v1.sherlock.metadata[0].name
    labels    = local.labels
  }

  spec {
    pod_selector {
      match_labels = local.web_labels
    }

    policy_types = ["Ingress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }

        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "traefik"
          }
        }
      }

      ports {
        protocol = "TCP"
        port     = "8000"
      }
    }
  }
}

# Sync pod: DNS via CoreDNS and HTTPS to public addresses (NVD), no internal networks
resource "kubernetes_network_policy_v1" "sync_egress" {
  metadata {
    name      = "sync-egress"
    namespace = kubernetes_namespace_v1.sherlock.metadata[0].name
    labels    = local.labels
  }

  spec {
    pod_selector {
      match_labels = local.sync_labels
    }

    policy_types = ["Egress"]

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }

        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }

      ports {
        protocol = "UDP"
        port     = "53"
      }

      ports {
        protocol = "TCP"
        port     = "53"
      }
    }

    egress {
      to {
        ip_block {
          cidr   = "0.0.0.0/0"
          except = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        }
      }

      ports {
        protocol = "TCP"
        port     = "443"
      }
    }
  }
}
