from verdikt.parser import parse_requirements
from verdikt.fetcher import fetch_vulnerabilities

deps, bad = parse_requirements("examples/requirements-vulnerable.txt")
print("Parsed:", deps)
print("Malformed:", bad)

for dep in deps:
    vulns = fetch_vulnerabilities(dep.name, dep.version)
    print(f"\n{dep.name} {dep.version}: {len(vulns)} known vulnerabilities")
    for v in vulns[:3]:
        print("   -", v.get("id"), "-", v.get("summary", "no summary")[:70])
        from verdikt.parser import parse_requirements
from verdikt.fetcher import fetch_vulnerabilities

deps, bad = parse_requirements("examples/requirements-vulnerable.txt")
print("Parsed:", deps)
print("Malformed:", bad)

for dep in deps:
    vulns = fetch_vulnerabilities(dep.name, dep.version)
    print(f"\n{dep.name} {dep.version}: {len(vulns)} known vulnerabilities")
    for v in vulns[:3]:
        print("   -", v.get("id"), "-", v.get("summary", "no summary")[:70])