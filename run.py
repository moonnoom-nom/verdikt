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
        from verdikt.policy import load_policy

# Loading both policies proves the loader handles contrasting configurations —
# these two files are the demo: same code, swap the policy, verdict flips.
dev = load_policy("examples/policy-dev.json")
prod = load_policy("examples/policy-prod.json")
print("\nDev policy:", dev)
print("Prod policy:", prod)
# Deliberate failure case: proves FR05 rejects invalid input with a
# field-level error rather than silently accepting a malformed policy.

