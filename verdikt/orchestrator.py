from verdikt.parser import Dependency
from verdikt.fetcher import fetch_vulnerabilities
from verdikt.severity import extract_base_score
from verdikt.scoring import score_vulnerability, unscored
from verdikt.decision import decide, Decision
from verdikt.policy import Policy


def scan_project(deps: list[Dependency], policy: Policy) -> Decision:
    """Run the full pipeline for every dependency and return one project-wide decision.

    This is the piece that turns five separately-tested modules into one
    actual product: without it, the tool can only ever report on one
    hand-picked package at a time, never a real project.
    """
    all_scored = []

    for dep in deps:
        # Cache means every dependency already seen costs nothing extra on a
        # repeat scan (FR03) — a real project scan runs often, so this is
        # exactly where that matters.
        vulns = fetch_vulnerabilities(dep.name, dep.version)

        for vuln in vulns:
            base_score, reason = extract_base_score(vuln)
            if base_score is not None:
                all_scored.append(
                    score_vulnerability(vuln["id"], dep.name, dep.version, base_score, policy)
                )
            else:
                # Never dropped silently — an unscored finding still reaches
                # the decision engine and forces at least a WARN there.
                all_scored.append(unscored(vuln["id"], dep.name, dep.version, reason))

    # One decision across every dependency in the project — the worst finding
    # anywhere determines the whole project's fate, not just one package's.
    # That's the actual job of a CI gate: gating the build, not one dependency
    # scanned in isolation.
    return decide(all_scored, policy)