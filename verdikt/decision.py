from enum import Enum
from typing import NamedTuple

from verdikt.policy import Policy
from verdikt.scoring import ScoredVulnerability


class Verdict(str, Enum):
    # Inherits str so the value serialises directly to JSON and prints cleanly,
    # while Enum prevents typos: Verdict.BLOCK fails loudly if misspelled,
    # whereas a bare "block" string would fail silently in a comparison.
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class Decision(NamedTuple):
    verdict: Verdict
    exit_code: int
    contributing: list[ScoredVulnerability]
    summary: str


def decide(scored: list[ScoredVulnerability], policy: Policy) -> Decision:
    """Determine an overall verdict from scored vulnerabilities and policy thresholds."""
    if not scored:
        return Decision(Verdict.ALLOW, 0, [], "No known vulnerabilities found.")

    unscored_items = [v for v in scored if v.raw_score is None]
    scoreable = [v for v in scored if v.raw_score is not None]

    blocking = [v for v in scoreable if v.raw_score >= policy.block_threshold]
    warning = [v for v in scoreable if policy.warn_threshold <= v.raw_score < policy.block_threshold]
    # Named explicitly rather than left as an implied leftover count, so it
    # can be reported even when the overall verdict is WARN because of
    # unscored items, not because any finding actually sits in WARN range.
    allow = [v for v in scoreable if v.raw_score < policy.warn_threshold]

    contributing = (
        sorted(blocking, key=lambda v: -v.raw_score)
        + sorted(warning, key=lambda v: -v.raw_score)
        + unscored_items
    )

    if blocking:
        parts = [f"{len(blocking)} blocking finding(s) at or above {policy.block_threshold}"]
        if warning:
            parts.append(f"{len(warning)} additional finding(s) at WARN level")
        if unscored_items:
            parts.append(f"{len(unscored_items)} additional unscored finding(s) requiring review")
        return Decision(Verdict.BLOCK, 1, contributing, "; ".join(parts) + ".")

    if warning or unscored_items:
        parts = []
        if warning:
            parts.append(
                f"{len(warning)} finding(s) between warn ({policy.warn_threshold}) "
                f"and block ({policy.block_threshold})"
            )
        if allow:
            # Even inside a WARN verdict, findings that scored clean must not
            # vanish from the text — otherwise "10 of 10 evaluated" has
            # nothing in the summary itself accounting for 8 of them.
            parts.append(f"{len(allow)} scored finding(s) below the warning threshold")
        if unscored_items:
            parts.append(f"{len(unscored_items)} unscored finding(s) requiring review")
        return Decision(Verdict.WARN, 0, contributing, "; ".join(parts) + ".")

    return Decision(Verdict.ALLOW, 0, [], f"All {len(allow)} finding(s) below the warning threshold.")