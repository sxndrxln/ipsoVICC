# IST/SOLL tracking

Kept up to date during implementation; becomes the IST/SOLL chapter of the documentation.

| Component | Planned (SOLL) | Status (IST) | Date |
|---|---|---|---|
| Repo skeleton | Structure, .gitignore, example files | done | 2026-10-25 |
| VM provisioning | Ansible: cloud-init template + clone on Proxmox | done | 2026-10-25 |
| k3s | Ansible: single-node k3s, kubeconfig fetched locally | done | 2026-10-26 |
| App | FastAPI: web UI (open / history / apps) + REST API + /docs | done (local)<br>done (container) | 2026-10-26<br>2026-10-29 |
| Vulnerability sync | NVD API 2.0 (incl. CISA KEV fields) → SQLite | done (local)<br>done (container) | 2026-10-26<br>2026-10-29 |
| Container image | Dockerfile, GitHub Actions → Docker Hub (public) | built locally<br>built by GitHub Actions | 2026-10-26<br>2026-10-26 |
| Workloads | Terraform: Namespace, Secret, ConfigMap, PVC, Deployment, Service, Ingress, CronJob | done | 2026-10-29 |
| Publication | NPM → sherlock.beste.host, TLS (Let's Encrypt) | done | 2026-10-29 |
| Scaling / HA | Theory only (single node, SQLite) | not planned | Covered in reflection |
