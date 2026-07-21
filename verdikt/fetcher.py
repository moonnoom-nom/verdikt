import requests
from verdikt.cache import read_cache, write_cache
OSV_URL = "https://api.osv.dev/v1/query"

def fetch_vulnerabilities(package: str, version:str, use_cache: bool = True) -> list[dict]:
    """ Query the OSV database for known vulnerabilities in a PyPI package version."""
    if use_cache:
        cached = read_cache(package, version)
        if cached is not None:
            return cached
    payload = {
        "package": {"name": package, "ecosystem": "PyPI"},
        "version": version,
    }
    response = requests.post(OSV_URL, json=payload, timeout=10)
    response.raise_for_status()
    vulns = response.json().get("vulns", [])

    if use_cache:
        write_cache(package, version, vulns)

    return vulns
