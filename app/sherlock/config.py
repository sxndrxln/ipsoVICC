import os
from pathlib import Path

# Settings come from environment variables, the defaults fit local development
REPO_ROOT = Path(__file__).resolve().parents[2]

DB_PATH = Path(os.environ.get("SHERLOCK_DB_PATH", "sherlock.db"))

APPS_FILE = Path(os.environ.get("SHERLOCK_APPS_FILE", REPO_ROOT / "data" / "apps.yaml"))

# Optional, with a key the NVD allows more requests (see nvd.py)
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
NVD_API_URL = os.environ.get("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
