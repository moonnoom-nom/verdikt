import json
from pathlib import Path

CACHE_DIR = Path(".cache")


def _cache_path(package: str, version: str) -> Path:
    return CACHE_DIR / f"{package}@{version}.json"


def read_cache(package: str, version: str) -> list[dict] | None:
    path = _cache_path(package, version)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def write_cache(package: str, version: str, vulns: list[dict]) -> None:
    CACHE_DIR.mkdir(exist_ok=True)
    _cache_path(package, version).write_text(json.dumps(vulns))