"""RQ2: which policy attribute exerts the greatest influence on score and verdict?

A one-factor-at-a-time comparison from a single baseline would give an answer
that depends on which baseline was chosen, because the scoring model is
multiplicative — the effect of changing one attribute depends on the values of
the other two. This module therefore scores every vulnerability under all 27
context combinations (3 environment x 3 exposure x 3 sensitivity) and reports
each attribute's mean marginal effect across all of them.
"""

import csv
import json
from itertools import product
from pathlib import Path
from statistics import mean

from verdikt.parser import parse_requirements
from verdikt.policy import Policy
from verdikt.fetcher import fetch_vulnerabilities
from verdikt.severity import extract_base_score
from verdikt.scoring import score_vulnerability, classify


# Thresholds are held constant at the values used throughout the evaluation.
# Only context varies, so any movement is attributable to context alone.
WARN_THRESHOLD = 4.0
BLOCK_THRESHOLD = 7.0

ENVIRONMENTS = ["development", "staging", "production"]
EXPOSURES = ["air-gapped", "internal", "internet-facing"]
SENSITIVITIES = ["public", "internal", "confidential"]

REPOSITORIES = [
    ("contoso-ads-2016", "repos/contoso-ads.txt"),
    ("azure-python-labs-2019", "repos/azure-python-labs.txt"),
    ("functions-data-cleaning-2019", "repos/functions-data-cleaning.txt"),
    ("aks-openai-2023", "repos/aks-openai.txt"),
    ("assistant-openai-2024", "repos/azure-assistant-openai.txt"),
]


def build_policy(env: str, exp: str, sens: str) -> Policy:
    return Policy(
        environment_tier=env,
        network_exposure=exp,
        data_sensitivity=sens,
        warn_threshold=WARN_THRESHOLD,
        block_threshold=BLOCK_THRESHOLD,
    )


def collect_base_scores() -> list[tuple[str, str, str, float]]:
    """Gather every scoreable vulnerability once, across all repositories.

    Collected once rather than per-combination because the base scores do not
    change — only the weights applied to them do. This turns 27 full scans into
    one scan plus 27 cheap arithmetic passes.
    """
    findings = []
    for repo_name, path in REPOSITORIES:
        deps, _ = parse_requirements(path)
        for dep in deps:
            for vuln in fetch_vulnerabilities(dep.name, dep.version):
                base, _reason = extract_base_score(vuln)
                if base is not None:
                    findings.append((repo_name, dep.name, vuln["id"], base))
    return findings


def verdict_for(score: float) -> str:
    """Per-finding verdict, using the same thresholds as the decision engine."""
    if score >= BLOCK_THRESHOLD:
        return "BLOCK"
    if score >= WARN_THRESHOLD:
        return "WARN"
    return "ALLOW"


def run() -> None:
    findings = collect_base_scores()
    print(f"Collected {len(findings)} scoreable findings across {len(REPOSITORIES)} repositories.")

    # Score every finding under every one of the 27 context combinations.
    # Key: (env, exp, sens) -> list of (raw_score, band, verdict)
    grid = {}
    for env, exp, sens in product(ENVIRONMENTS, EXPOSURES, SENSITIVITIES):
        policy = build_policy(env, exp, sens)
        results = []
        for _repo, pkg, vid, base in findings:
            scored = score_vulnerability(vid, pkg, "n/a", base, policy)
            results.append((scored.raw_score, scored.band, verdict_for(scored.raw_score)))
        grid[(env, exp, sens)] = results

    # Marginal effect of each attribute: for every combination of the OTHER two
    # attributes, measure the score movement between this attribute's lowest
    # and highest setting, then average across all those combinations. This
    # avoids the result depending on one arbitrarily chosen baseline.
    attribute_effects = {}

    def marginal(attr_name, levels, position):
        deltas = []
        verdict_changes = []
        # Every combination of the two attributes NOT under test.
        others = [
            (a, b) for a, b in product(
                *[lv for i, lv in enumerate([ENVIRONMENTS, EXPOSURES, SENSITIVITIES]) if i != position]
            )
        ]
        for other in others:
            key_low = list(other)
            key_high = list(other)
            key_low.insert(position, levels[0])
            key_high.insert(position, levels[-1])
            low = grid[tuple(key_low)]
            high = grid[tuple(key_high)]
            deltas.append(mean(h[0] - l[0] for l, h in zip(low, high)))
            changed = sum(1 for l, h in zip(low, high) if l[2] != h[2])
            verdict_changes.append(changed / len(low))
        attribute_effects[attr_name] = {
            "mean_score_delta": round(mean(deltas), 3),
            "mean_verdict_change_rate": round(mean(verdict_changes), 3),
            "weight_range": f"{levels[0]} to {levels[-1]}",
        }

    marginal("environment_tier", ENVIRONMENTS, 0)
    marginal("network_exposure", EXPOSURES, 1)
    marginal("data_sensitivity", SENSITIVITIES, 2)

    Path("evaluation").mkdir(exist_ok=True)

    with open("evaluation/attribute_analysis.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["attribute", "mean_score_delta", "mean_verdict_change_rate", "weight_range"])
        for attr, vals in attribute_effects.items():
            w.writerow([attr, vals["mean_score_delta"], vals["mean_verdict_change_rate"], vals["weight_range"]])

    Path("evaluation/attribute_analysis.json").write_text(
        json.dumps({
            "findings_analysed": len(findings),
            "context_combinations": len(grid),
            "thresholds": {"warn": WARN_THRESHOLD, "block": BLOCK_THRESHOLD},
            "attribute_effects": attribute_effects,
        }, indent=2)
    )

    print(f"\nScored under {len(grid)} context combinations.\n")
    print(f"{'Attribute':<22}{'Score delta':>14}{'Verdict change':>18}{'Weight range':>18}")
    for attr, v in attribute_effects.items():
        print(f"{attr:<22}{v['mean_score_delta']:>14}{v['mean_verdict_change_rate']:>18}{v['weight_range']:>18}")

    ranked = sorted(attribute_effects.items(), key=lambda kv: -kv[1]["mean_score_delta"])
    print(f"\nGreatest mean score movement: {ranked[0][0]}")
    print("Note: attribute weight ranges are not equal, so this ranking is a property")
    print("of the proposed weighting model, not an intrinsic property of the attributes.")


if __name__ == "__main__":
    run()