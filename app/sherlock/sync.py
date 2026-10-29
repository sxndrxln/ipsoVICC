# Sync job, runs as Kubernetes CronJob (python -m sherlock.sync).
# Queries the NVD for every app in the inventory and updates the database.
import logging
import sqlite3
import sys
from datetime import UTC, datetime

from sherlock import config
from sherlock.db import connect, init_db
from sherlock.inventory import App, load_apps
from sherlock.nvd import NvdClient, NvdError, Vulnerability, cpe_prefix, parse

log = logging.getLogger("sherlock.sync")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# CVEs of all CPEs of an app, without duplicates
def fetch_vulnerabilities(client: NvdClient, app: App) -> dict[str, Vulnerability]:
    match_strings = app.match_strings()
    prefixes = [cpe_prefix(m) for m in match_strings]
    found: dict[str, Vulnerability] = {}
    for match_string in match_strings:
        for record in client.cves_for(match_string, app.keyword):
            found.setdefault(record["id"], parse(record, prefixes, app.version))
    return found


# Saves the result of one app. Found CVEs are inserted or reopened.
def store(conn: sqlite3.Connection, app: App, found: dict[str, Vulnerability]) -> tuple[int, int]:
    now = _now()
    row = conn.execute("SELECT version FROM apps WHERE id = ?", (app.id,)).fetchone()
    version_changed = row is not None and row["version"] != app.version

    for vuln in found.values():
        conn.execute(
            """
            INSERT INTO findings (app_id, cve_id, status, severity, score, published, description,
                                  fixed_in, patch_available, patch_url, kev, kev_added,
                                  first_seen, last_seen, opened_version)
            VALUES (?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (app_id, cve_id) DO UPDATE SET
                status = 'open', resolved_at = NULL, resolved_version = NULL, resolution = NULL,
                severity = excluded.severity, score = excluded.score,
                published = excluded.published, description = excluded.description,
                fixed_in = excluded.fixed_in, patch_available = excluded.patch_available,
                patch_url = excluded.patch_url, kev = excluded.kev, kev_added = excluded.kev_added,
                last_seen = excluded.last_seen
            """,
            (
                app.id, vuln.cve_id, vuln.severity, vuln.score, vuln.published, vuln.description,
                vuln.fixed_in, int(vuln.patch_available), vuln.patch_url, int(vuln.kev), vuln.kev_added,
                now, now, app.version,
            ),
        )

    # Open CVEs that were not found anymore go to the history:
    # "updated" if the version in apps.yaml changed, otherwise the NVD changed its data
    still_open = [r["cve_id"] for r in conn.execute(
        "SELECT cve_id FROM findings WHERE app_id = ? AND status = 'open'", (app.id,)
    )]
    gone = [cve_id for cve_id in still_open if cve_id not in found]
    conn.executemany(
        """
        UPDATE findings SET status = 'resolved', resolved_at = ?, resolved_version = ?, resolution = ?
        WHERE app_id = ? AND cve_id = ?
        """,
        [(now, app.version, "updated" if version_changed else "not_applicable", app.id, c) for c in gone],
    )

    conn.execute(
        """
        INSERT INTO apps (id, name, category, version, last_synced, sync_ok)
        VALUES (?, ?, ?, ?, ?, 1)
        ON CONFLICT (id) DO UPDATE SET name = excluded.name, category = excluded.category,
            version = excluded.version, last_synced = excluded.last_synced, sync_ok = 1
        """,
        (app.id, app.name, app.category, app.version, now),
    )
    return len(found), len(gone)


# Query failed: keep the previous findings and only flag the app
def mark_failed(conn: sqlite3.Connection, app: App) -> None:
    conn.execute(
        """
        INSERT INTO apps (id, name, category, version, sync_ok) VALUES (?, ?, ?, ?, 0)
        ON CONFLICT (id) DO UPDATE SET name = excluded.name, category = excluded.category, sync_ok = 0
        """,
        (app.id, app.name, app.category, app.version),
    )


# One complete sync run, logged in sync_runs. Exit code 1 if an app failed.
def run() -> int:
    apps = load_apps(config.APPS_FILE)
    init_db(config.DB_PATH)
    conn = connect(config.DB_PATH)
    run_id = conn.execute(
        "INSERT INTO sync_runs (started_at, status) VALUES (?, 'running')", (_now(),)
    ).lastrowid
    conn.commit()

    client = NvdClient(config.NVD_API_URL, config.NVD_API_KEY)
    failed: list[str] = []
    completed = False
    try:
        for app in apps:
            try:
                found = fetch_vulnerabilities(client, app)
            except NvdError as exc:
                log.error("%s: NVD query failed, keeping previous state (%s)", app.id, exc)
                mark_failed(conn, app)
                failed.append(app.id)
            else:
                open_count, resolved = store(conn, app, found)
                log.info("%s %s: %d open, %d moved to history", app.id, app.version, open_count, resolved)
            conn.commit()

        # Remove apps that are no longer in the inventory
        ids = [app.id for app in apps]
        conn.execute(f"DELETE FROM apps WHERE id NOT IN ({','.join('?' * len(ids))})", ids)
        completed = True
    finally:
        client.close()
        if not completed:
            status, message = "failed", "aborted by an unexpected error"
        elif failed:
            status, message = "failed", f"failed: {', '.join(failed)}"
        else:
            status, message = "ok", f"{len(apps)} apps synced"
        conn.execute(
            "UPDATE sync_runs SET finished_at = ?, status = ?, message = ? WHERE id = ?",
            (_now(), status, message, run_id),
        )
        conn.commit()
        conn.close()
    return 1 if failed else 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    sys.exit(run())
