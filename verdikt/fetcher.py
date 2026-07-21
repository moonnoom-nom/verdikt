import requests
OSV_URL = "https://api.osv.dev/v1/query"

def fetch_vulnerabilities(package: str, version:str) -> list[dict]:
    """ Query the OSV database for known vulnerabilities in a PyPI package version."""
    payload = {
        "package": {"name": package, "ecosystem": "PyPI"},
        "version": version,
    }
    response = requests.post(OSV_URL, json=payload, timeout=10)
    response.raise_for_status()
    return response.json().get("vulns", [])
