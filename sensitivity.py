"""Sensitivity analysis: re-runs the evaluation under alternative weight
configurations to test whether gating decisions are stable (RQ3).

The weights used in the main evaluation derive from the CVSS v3.1
environmental metric structure and reasoned argument, not empirical
calibration. This module tests whether the conclusions survive plausible
variation in those values, which is what makes the choice defensible rather
than arbitrary.
"""

import csv
import json
from pathlib import Path

from verdikt.parser import parse_requirements
from verdikt.policy import load_policy
from verdikt.fetcher import fetch_vulnerabilities
from verdikt.severity import extract_base_score
from verdikt.scoring import score_vulnerability, WeightConfiguration
from verdikt.decision import decide


LOW_CONTEXT = load_policy("examples/policy-context-low.json")
HIGH_CONTEXT = load_policy("examples/policy-context-high.json")


# Three configurations spanning a plausible range of organisational risk
# posture. All preserve the attenuation property (no weight above 1.0), so the
# contextual score can never exceed the CVSS base score in any of them.
CONFIGURATIONS = {
    # Conservative: mild attenuation. An organisation that trusts context only
    # slightly, keeping scores close to base values. This is the configuration
    # most likely to still block under low context, making it the strongest
    # test of whether the finding depends on extreme weights.
    "conservative": WeightConfiguration(
        environment={"production": 1.0, "staging": 0.9, "development": 0.8},
        exposure={"internet-facing": 1.0, "internal": 0.9, "air-gapped": 0.8},
        sensitivity={"confidential": 1.0, "internal": 0.95, "public": 0.9},
    ),
    # Default: the weights used in the main evaluation.
    "default": WeightConfiguration(
        environment={"production": 1.0, "staging": 0.75, "development": 0.5},
        exposure={"internet-facing": 1.0, "internal": 0.7, "air-gapped": 0.4},
        sensitivity={"confidential": 1.0, "internal": 0.8, "public": 0.6},
    ),
    # Aggressive: strong attenuation. An organisation heavily discounting
    # low-risk contexts. Bounds the range in the other direction.
    "aggressive": WeightConfiguration(
        environment={"production": 1.0, "staging": 0.6, "development": 0.3},
        exposure={"internet-facing": 1.0, "internal": 0.5, "air-gapped": 0.2},
        sensitivity={"confidential": 1.0, "internal": 0.6, "public": 0.4},
    ),
}


def score_all(deps, policy, weights):
    """Score every vulnerability in a dependency set under one configuration."""
    scored = []
    for dep in deps:
        for vuln in fetch_vulnerabilities(dep.name, dep.version):
            base_score, _ = extract_base_score(vuln)
            if base_score is not None:
                scored.append(
                    score_vulnerability(
                        vuln["id"], dep.name, dep.version, base_score, policy, weights
                    )
                )
    return scored


def analyse_repository(name: str, requirements_path: str) -> list[dict]:
    """Run one repository under all three weight configurations."""
    deps, _ = parse_requirements(requirements_path)
    rows = []

    for config_name, weights in CONFIGURATIONS.items():
        low_scored = score_all(deps, LOW_CONTEXT, weights)
        high_scored = score_all(deps, HIGH_CONTEXT, weights)

        low_decision = decide(low_scored, LOW_CONTEXT)
        high_decision = decide(high_scored, HIGH_CONTEXT)

        # Matched by vulnerability ID so each vulnerability is compared against
        # itself across the two contexts.
        low_by_id = {v.vulnerability_id: v for v in low_scored}
        high_by_id = {v.vulnerability_id: v for v in high_scored}
        shared = set(low_by_id) & set(high_by_id)

        if shared:
            deltas = [
                abs(high_by_id[i].raw_score - low_by_id[i].raw_score) for i in shared
            ]
            mean_delta = sum(deltas) / len(deltas)
            band_changes = sum(
                1 for i in shared if low_by_id[i].band != high_by_id[i].band
            )
            band_change_rate = band_changes / len(shared)
        else:
            mean_delta = 0.0
            band_change_rate = 0.0

        # Does anything block under LOW context? Under default weights the
        # answer is no by arithmetic; the conservative configuration is where
        # this can differ, which is the point of running all three.
        low_blocking = sum(
            1 for v in low_scored if v.raw_score >= LOW_CONTEXT.block_threshold
        )

        rows.append({
            "repository": name,
            "configuration": config_name,
            "scored_findings": len(shared),
            "low_context_verdict": low_decision.verdict.value,
            "high_context_verdict": high_decision.verdict.value,
            "verdict_changed": low_decision.verdict != high_decision.verdict,
            "context_sensitivity_score": round(mean_delta, 2),
            "band_change_rate": round(band_change_rate, 3),
            "low_context_blocking_count": low_blocking,
        })

    return rows


def run_sensitivity_analysis(repositories, output_dir: str = "evaluation") -> None:
    Path(output_dir).mkdir(exist_ok=True)
    all_rows = []

    for name, path in repositories:
        print(f"Analysing {name}...")
        try:
            all_rows.extend(analyse_repository(name, path))
        except Exception as exc:
            print(f"  FAILED: {exc}")

    csv_path = Path(output_dir) / "sensitivity.csv"
    json_path = Path(output_dir) / "sensitivity.json"

    if all_rows:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
            writer.writeheader()
            writer.writerows(all_rows)

    json_path.write_text(json.dumps(all_rows, indent=2))

    print(f"\nWrote {len(all_rows)} rows to {csv_path} and {json_path}")

    # Decision stability: proportion of repository-configuration pairs where
    # the verdict still changed between contexts. This is the direct answer to
    # RQ3 — if the finding held only under one weight setting, the conclusion
    # would depend on an arbitrary choice.
    changed = sum(1 for r in all_rows if r["verdict_changed"])
    print(f"Verdict changed between contexts in {changed}/{len(all_rows)} repository-configuration pairs.")
    print(f"Decision stability: {round(changed / len(all_rows) * 100, 1)}%")


if __name__ == "__main__":
    REPOSITORIES = [
        ("contoso-ads-2016", "repos/contoso-ads.txt"),
        ("azure-python-labs-2019", "repos/azure-python-labs.txt"),
        ("functions-data-cleaning-2019", "repos/functions-data-cleaning.txt"),
        ("aks-openai-2023", "repos/aks-openai.txt"),
        ("assistant-openai-2024", "repos/azure-assistant-openai.txt"),
    ]
    run_sensitivity_analysis(REPOSITORIES)