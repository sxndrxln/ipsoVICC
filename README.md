# ipsoVICC
Dieses Repository wird verwendet um sämtliche Dokumentationen wie auch Code für die Praxisarbeit im Fach VICC der ipso Bildung AG zu sichern und versionieren.

## Projekt: sherlock
Webanwendung, die für eine definierte Liste von Applikationen (Demo-Inventar) veröffentlichte Schwachstellen anzeigt – offen oder bereits behoben (History) sowie ob ein Patch verfügbar ist. Datenquelle: NVD API 2.0 (NIST); die Angaben aus dem CISA-Katalog Known Exploited Vulnerabilities (KEV) liefert die NVD direkt in ihren CVE-Daten mit.

Die Anwendung läuft containerisiert auf einem Single-Node-k3s-Cluster in einer VM auf Proxmox VE.

| Schicht | Werkzeug | Ort |
|---|---|---|
| VM (Cloud-Init-Template + Klon) und k3s | Ansible | [ansible/](ansible/) |
| Kubernetes-Ressourcen der App | Terraform | [terraform/](terraform/) |
| Applikation (Web-UI + REST-API) | Python / FastAPI, Docker | [app/](app/) |
| Demo-Inventar (Applikationen + Versionen) | YAML → ConfigMap | [data/apps.yaml](data/apps.yaml) |
| Container-Image Build | GitHub Actions → Docker Hub | [.github/workflows/](.github/workflows/) |
| Dokumentation, IST/SOLL | – | [docs/](docs/) |

## Voraussetzungen
- Ansible (core ≥ 2.17) mit `ansible-galaxy collection install -r ansible/requirements.yml`, Python-Pakete `proxmoxer` und `requests`
- Terraform ≥ 1.6
- Proxmox VE mit API-Zugang, NVD-API-Key (kostenlos)

## Secrets
Es werden nur Vorlagen eingecheckt:
- `ansible/inventories/group_vars/all/vault.example.yml` → `vault.yml` (mit `ansible-vault` verschlüsseln)
- `ansible/inventories/host_vars/srv-k8s01/vault.example.yml` → `vault.yml` (mit `ansible-vault` verschlüsseln)
- `terraform/terraform.tfvars.example` → `terraform.tfvars`
- `app/.env.example` → `.env` (nur für die lokale Entwicklung)
- GitHub-Repository-Secrets für den Image-Build: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`

## Applikation lokal starten
```
cd app
python3.14 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements.txt
set -a; source .env; set +a
.venv/bin/python -m sherlock.sync          # Abgleich mit der NVD
.venv/bin/uvicorn sherlock.main:app        # http://127.0.0.1:8000, API-Doku unter /docs
```

Abhängigkeiten werden in `app/requirements.in` gepflegt; `requirements.txt` (alle Pakete inkl. Hashes) wird daraus mit `pip-compile --allow-unsafe --generate-hashes --strip-extras requirements.in` erzeugt (im Ordner `app/`).

## Image-Build
Ein veröffentlichtes GitHub-Release (z.B. Tag `v1.0.0`) baut das Image, prüft es mit Grype und Docker Scout auf Schwachstellen und lädt es als `sxndrxln/sherlock:1.0.0` und `latest` nach Docker Hub.
