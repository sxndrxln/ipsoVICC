from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class App:
    id: str
    name: str
    category: str
    version: str
    cpes: list[str] = field(default_factory=list)
    keyword: str | None = None

    def match_strings(self) -> list[str]:
        return [cpe.replace("{version}", self.version) for cpe in self.cpes]


def load_apps(path: Path) -> list[App]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    apps: list[App] = []
    seen: set[str] = set()
    for entry in data.get("apps", []):
        missing = [key for key in ("id", "name", "version", "cpes") if not entry.get(key)]
        if missing:
            raise ValueError(f"App entry {entry!r} is missing {', '.join(missing)}")
        if entry["id"] in seen:
            raise ValueError(f"Duplicate app id {entry['id']!r}")
        if any("{version}" not in cpe for cpe in entry["cpes"]):
            raise ValueError(f"Every CPE of {entry['id']!r} needs a {{version}} placeholder")
        seen.add(entry["id"])
        apps.append(
            App(
                id=str(entry["id"]),
                name=str(entry["name"]),
                category=str(entry.get("category", "")),
                version=str(entry["version"]),
                cpes=[str(cpe) for cpe in entry["cpes"]],
                keyword=entry.get("keyword"),
            )
        )
    return apps
