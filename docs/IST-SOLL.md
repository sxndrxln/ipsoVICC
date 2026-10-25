# IST/SOLL tracking

Kept up to date during implementation; becomes the IST/SOLL chapter of the documentation.

| Component | Planned (SOLL) | Status (IST) | Note |
|---|---|---|---|
| Repo skeleton | Structure, .gitignore, example files | done | 2026-10-25 |
| VM provisioning | Ansible: cloud-init template + clone on Proxmox | done | 2026-10-25 |
| k3s | Ansible: single-node k3s, kubeconfig fetched locally | open | |
| App | FastAPI: web UI (open / history) + REST API + /docs | open | |
| Vulnerability sync | NVD API 2.0 + CISA KEV → SQLite, CronJob | open | |
| Container image | Dockerfile, GitHub Actions → Docker Hub (public) | open | |
| Workloads | Terraform: Namespace, Secret, ConfigMap, PVC, Deployment, Service, Ingress, CronJob | open | |
| Publication | NPM → sherlock.beste.host, TLS (Let's Encrypt) | open | |
| Scaling / HA | Theory only (single node, SQLite) | not planned | Covered in reflection |
