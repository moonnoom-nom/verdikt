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
from verdikt.scoring import score_vulnerability

# Same vulnerability, two policies — this contrast IS the thesis.
for pol, label in [(dev, "DEV"), (prod, "PROD")]:
    result = score_vulnerability("GHSA-9hjg-9r4m-mvj7", "requests", "2.19.0", 7.5, pol)
    print(f"\n{label}: {result.contextual_score} ({result.band})")
    print(f"  {result.rationale}")
from verdikt.decision import decide

# The demo: same vulnerability set, two policies, contrasting verdicts.
for pol, label in [(dev, "DEV"), (prod, "PROD")]:
    scored = [score_vulnerability("GHSA-9hjg-9r4m-mvj7", "requests", "2.19.0", 7.5, pol)]
    d = decide(scored, pol)
    print(f"\n{label}: {d.verdict.value}  (exit {d.exit_code})")
    print(f"  {d.summary}")
    for v in d.contributing:
        print(f"  - {v.package} {v.version}: {v.contextual_score} ({v.band})")