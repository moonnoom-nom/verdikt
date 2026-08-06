"""Evaluation harness: runs Verdikt across multiple repositories under
contrasting policies and collects the metrics defined in Chapter 3.

Kept separate from cli.py because their jobs differ: cli.py gates one project
and exits, while this scans many projects and reports comparative statistics.
"""

import csv
import json
from pathlib import Path

from verdikt.parser import parse_requirements
from verdikt.policy import load_policy
from verdikt.orchestrator import scan_project
from verdikt.fetcher import fetch_vulnerabilities
from verdikt.severity import extract_base_score
from verdikt.scoring import score_vulnerability


# The context-controlled pair: identical thresholds, differing only in the
# three contextual attributes. This is what makes RQ1/RQ2 evidence valid —
# any verdict change must come from context, not from a stricter threshold.
LOW_CONTEXT = load_policy("examples/policy-context-low.json")
HIGH_CONTEXT = load_policy("examples/policy-context-high.json")

# Baseline threshold for the context-free comparison. CVSS 7.0 is the
# High/Critical boundary in the v3.1 specification — chosen in advance rather
# than tuned to produce a favourable result.
BASELINE_BLOCK_THRESHOLD = 7.0


def evaluate_repository(name: str, requirements_path: str) -> dict:
    """Scan one repository under both policies and compute its metrics."""
    deps, malformed = parse_requirements(requirements_path)

    low = scan_project(deps, LOW_CONTEXT)
    high = scan_project(deps, HIGH_CONTEXT)

    # Score every finding independently of the decision output. decide() only
    # surfaces findings that crossed a threshold, so reading contributing[]
    # here would silently exclude every finding that attenuated below the warn
    # line under low context — precisely the population this metric measures.
    all_scored_low = []
    all_scored_high = []

    for dep in deps:
        vulns = fetch_vulnerabilities(dep.name, dep.version)
        for vuln in vulns:
            base_score, reason = extract_base_score(vuln)
            if base_score is not None:
                all_scored_low.append(
                    score_vulnerability(vuln["id"], dep.name, dep.version, base_score, LOW_CONTEXT)
                )
                all_scored_high.append(
                    score_vulnerability(vuln["id"], dep.name, dep.version, base_score, HIGH_CONTEXT)
                )

    # Matched by vulnerability ID so each vulnerability is compared to itself.
    low_by_id = {v.vulnerability_id: v for v in all_scored_low}
    high_by_id = {v.vulnerability_id: v for v in all_scored_high}
    shared_ids = set(low_by_id) & set(high_by_id)

    scored_pairs = [(low_by_id[i], high_by_id[i]) for i in shared_ids]

    if scored_pairs:
        deltas = [abs(h.raw_score - l.raw_score) for l, h in scored_pairs]
        context_sensitivity = sum(deltas) / len(deltas)
    else:
        context_sensitivity = 0.0

    # Band change rate: proportion of findings whose CVSS severity band differs
    # between contexts. Recorded separately from raw score movement because a
    # score can shift without crossing a band boundary.
    if scored_pairs:
        changed = sum(1 for l, h in scored_pairs if l.band != h.band)
        decision_change_rate = changed / len(scored_pairs)
    else:
        decision_change_rate = 0.0

    baseline_blocking = sum(
        1 for v in all_scored_high
        if v.base_score is not None and v.base_score >= BASELINE_BLOCK_THRESHOLD
    )
    verdikt_blocking_low = sum(
        1 for v in all_scored_low
        if v.raw_score is not None and v.raw_score >= LOW_CONTEXT.block_threshold
    )

    if baseline_blocking > 0:
        friction_reduction = 1 - (verdikt_blocking_low / baseline_blocking)
    else:
        # Explicitly not applicable rather than dividing by zero.
        friction_reduction = None

    return {
        "repository": name,
        "dependencies": len(deps),
        "malformed_lines": len(malformed),
        "total_findings": len(high.contributing),
        "scored_findings": len(scored_pairs),
        "unscored_findings": sum(1 for v in high.contributing if v.raw_score is None),
        "low_context_verdict": low.verdict.value,
        "high_context_verdict": high.verdict.value,
        "verdict_changed": low.verdict != high.verdict,
        "context_sensitivity_score": round(context_sensitivity, 2),
        "decision_change_rate": round(decision_change_rate, 3),
        "baseline_blocking_count": baseline_blocking,
        "verdikt_low_blocking_count": verdikt_blocking_low,
        "friction_reduction_ratio": (
            round(friction_reduction, 3) if friction_reduction is not None else "N/A"
        ),
    }


def run_evaluation(repositories: list[tuple[str, str]], output_dir: str = "evaluation") -> None:
    """Evaluate every repository and write results to CSV and JSON.

    Two output formats deliberately: CSV pastes directly into the dissertation
    as a table, JSON preserves full precision for later re-analysis.
    """
    Path(output_dir).mkdir(exist_ok=True)
    results = []

    for name, path in repositories:
        print(f"Evaluating {name}...")
        try:
            results.append(evaluate_repository(name, path))
        except Exception as exc:
            # A failure on one repository must not abandon the whole run —
            # partial results remain usable, and the failure is recorded.
            print(f"  FAILED: {exc}")
            results.append({"repository": name, "error": str(exc)})

    csv_path = Path(output_dir) / "results.csv"
    json_path = Path(output_dir) / "results.json"

    if results:
        fieldnames = sorted({k for r in results for k in r})
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

    json_path.write_text(json.dumps(results, indent=2))

    print(f"\nWrote {len(results)} results to {csv_path} and {json_path}")

    successful = [r for r in results if "error" not in r]
    if successful:
        changed = sum(1 for r in successful if r["verdict_changed"])
        print(f"Verdict changed under different context in {changed}/{len(successful)} repositories.")


if __name__ == "__main__":
    # Five archived Azure Sample applications, selected per the criteria in
    # Section 3.2.1: pinned dependencies, 10+ packages, spanning multiple
    # application domains and release eras (2016-2024). Archived repositories
    # were chosen deliberately: actively maintained projects remediate the
    # vulnerabilities the evaluation requires.
    REPOSITORIES = [
        ("contoso-ads-2016", "repos/contoso-ads.txt"),
        ("azure-python-labs-2019", "repos/azure-python-labs.txt"),
        ("functions-data-cleaning-2019", "repos/functions-data-cleaning.txt"),
        ("aks-openai-2023", "repos/aks-openai.txt"),
        ("assistant-openai-2024", "repos/azure-assistant-openai.txt"),
    ]
    run_evaluation(REPOSITORIES)