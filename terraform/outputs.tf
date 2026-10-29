# Shown after apply
output "url" {
  value = "https://${var.app_host}"
}

output "image" {
  value = var.app_image
}
