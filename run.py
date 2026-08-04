from verdikt.parser import parse_requirements
from verdikt.fetcher import fetch_vulnerabilities
from verdikt.policy import load_policy
from verdikt.severity import extract_base_score
from verdikt.scoring import score_vulnerability, unscored
from verdikt.decision import decide

# ---------------------------------------------------------------------------
# Step 1: parse the dependency file (FR01)
# ---------------------------------------------------------------------------
deps, bad = parse_requirements("examples/requirements-vulnerable.txt")
print("Parsed:", deps)
print("Malformed:", bad)

# ---------------------------------------------------------------------------
# Step 2: fetch known vulnerabilities for each dependency, using the cache
# where available (FR02, FR03). Raw records are kept so Step 4 can re-use
# them for severity extraction, instead of fetching twice.
# ---------------------------------------------------------------------------
all_vulns = {}
for dep in deps:
    vulns = fetch_vulnerabilities(dep.name, dep.version)
    all_vulns[dep.name] = vulns
    print(f"\n{dep.name} {dep.version}: {len(vulns)} known vulnerabilities")
    for v in vulns[:3]:
        print("   -", v.get("id"), "-", v.get("summary", "no summary")[:70])

# ---------------------------------------------------------------------------
# Step 3: load the two contrasting policies (FR05)
# ---------------------------------------------------------------------------
dev = load_policy("examples/policy-dev.json")
prod = load_policy("examples/policy-prod.json")
context_low = load_policy("examples/policy-context-low.json")
context_high = load_policy("examples/policy-context-high.json")


# ---------------------------------------------------------------------------
# Step 4: the real end-to-end pipeline. Every severity score below comes from
# a genuine OSV record via extract_base_score — no hardcoded numbers. Scoring
# ALL of requests's known vulnerabilities, not just one, means decide()'s
# worst-case logic actually has multiple findings to choose the worst from,
# which is the realistic case a CI pipeline would face.
# ---------------------------------------------------------------------------
print("\n--- FULL PIPELINE: requests 2.19.0 ---")

requests_vulns = all_vulns["requests"]

for pol, label in [(context_low, "LOW CONTEXT"), (context_high, "HIGH CONTEXT")]:
    scored = []
    for vuln in requests_vulns:
        base_score, reason = extract_base_score(vuln)
        if base_score is not None:
            scored.append(
                score_vulnerability(vuln["id"], "requests", "2.19.0", base_score, pol)
            )
        else:
            # Not silently dropped: an unscored finding still surfaces and
            # forces at least a WARN in decide() below.
            scored.append(unscored(vuln["id"], "requests", "2.19.0", reason))

    decision = decide(scored, pol)
    print(f"\n{label}: {decision.verdict.value}  (exit {decision.exit_code})")
    print(f"  {decision.summary}")
    # Reconciliation: proves the report accounts for every fetched record,
    # not just the ones that happened to cross a threshold.
    print(f"  ({len(scored)} of {len(requests_vulns)} fetched OSV records evaluated)")
    for v in decision.contributing:
        print(f"  - {v.vulnerability_id}: {v.contextual_score} ({v.band})")
        from verdikt.orchestrator import scan_project

print("\n--- PROJECT-WIDE SCAN: all 5 dependencies ---")
for pol, label in [(context_low, "LOW CONTEXT"), (context_high, "HIGH CONTEXT")]:
    decision = scan_project(deps, pol)
    print(f"\n{label}: {decision.verdict.value}  (exit {decision.exit_code})")
    print(f"  {decision.summary}")
    for v in decision.contributing:
        print(f"  - {v.package} {v.version} :: {v.vulnerability_id}: {v.contextual_score} ({v.band})")