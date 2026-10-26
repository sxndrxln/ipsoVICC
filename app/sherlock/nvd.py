import re
import time
from dataclasses import dataclass

import httpx

from sherlock import __version__

PAGE_SIZE = 2000

DELAY_WITHOUT_KEY = 6.5
DELAY_WITH_KEY = 3.0

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class NvdError(Exception):
    pass


@dataclass
class Vulnerability:
    cve_id: str
    published: str | None
    description: str
    severity: str | None
    score: float | None
    fixed_in: str | None
    patch_url: str | None
    kev: bool
    kev_added: str | None

    @property
    def patch_available(self) -> bool:
        return bool(self.fixed_in or self.patch_url)


class NvdClient:
    def __init__(self, api_url: str, api_key: str = "") -> None:
        headers = {"User-Agent": f"sherlock/{__version__}"}
        if api_key:
            headers["apiKey"] = api_key
        self._client = httpx.Client(base_url=api_url, headers=headers, timeout=60)
        self._delay = DELAY_WITH_KEY if api_key else DELAY_WITHOUT_KEY

    def close(self) -> None:
        self._client.close()

    def _get(self, params: dict) -> dict:
        for attempt in range(4):
            time.sleep(self._delay)
            try:
                response = self._client.get("", params=params)
            except httpx.HTTPError as exc:
                error = str(exc)
            else:
                if response.status_code == 200:
                    return response.json()
                error = f"HTTP {response.status_code} {response.headers.get('message', '')}".strip()
            time.sleep(10 * (attempt + 1))
        raise NvdError(error)

    def cves_for(self, match_string: str, keyword: str | None = None) -> list[dict]:
        params = {"virtualMatchString": match_string, "resultsPerPage": PAGE_SIZE}
        if keyword:
            params["keywordSearch"] = keyword
        records: list[dict] = []
        start = 0
        while True:
            data = self._get({**params, "startIndex": start})
            items = data.get("vulnerabilities")
            total = data.get("totalResults")
            if not isinstance(items, list) or not isinstance(total, int):
                raise NvdError(f"Malformed response for {match_string}")
            records.extend(item["cve"] for item in items)
            start += data.get("resultsPerPage", 0)
            if not data.get("resultsPerPage") or start >= total:
                break
        if len(records) != total:
            raise NvdError(f"Incomplete response for {match_string}: {len(records)} of {total} records")
        return records


def version_key(version: str) -> tuple:
    return tuple((1, int(t)) if t.isdigit() else (0, t) for t in re.findall(r"\d+|[a-z]+", version.lower()))


def _in_range(match: dict, version: str) -> bool:
    key = version_key(version)
    if (v := match.get("versionStartIncluding")) and key < version_key(v):
        return False
    if (v := match.get("versionStartExcluding")) and key <= version_key(v):
        return False
    if (v := match.get("versionEndIncluding")) and key > version_key(v):
        return False
    if (v := match.get("versionEndExcluding")) and key >= version_key(v):
        return False
    return True


def _cvss(cve: dict) -> tuple[str | None, float | None]:
    metrics = cve.get("metrics", {})
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if entries := metrics.get(name):
            entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = entry["cvssData"]
            severity = data.get("baseSeverity") or entry.get("baseSeverity")
            return severity, data.get("baseScore")
    return None, None


def parse(cve: dict, cpe_prefixes: list[str], version: str) -> Vulnerability:
    fixed: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable") or not match["criteria"].startswith(tuple(cpe_prefixes)):
                    continue
                end = match.get("versionEndExcluding")
                try:
                    if end and _in_range(match, version):
                        fixed.append(end)
                except (TypeError, ValueError):
                    continue

    patch_url = next(
        (ref["url"] for ref in cve.get("references", []) if "Patch" in ref.get("tags", [])),
        None,
    )
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    severity, score = _cvss(cve)
    return Vulnerability(
        cve_id=cve["id"],
        published=(cve.get("published") or "")[:10] or None,
        description=description,
        severity=severity,
        score=score,
        fixed_in=min(fixed, key=version_key) if fixed else None,
        patch_url=patch_url,
        kev="cisaExploitAdd" in cve,
        kev_added=cve.get("cisaExploitAdd"),
    )


def cpe_prefix(match_string: str) -> str:
    return ":".join(match_string.split(":")[:5]) + ":"
