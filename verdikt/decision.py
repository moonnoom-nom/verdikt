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
    # Only the vulnerabilities that actually caused the verdict, not every
    # finding — a developer needs to know what to fix, not what was scanned.
    contributing: list[ScoredVulnerability]
    summary: str


def decide(scored: list[ScoredVulnerability], policy: Policy) -> Decision:
    """Determine an overall verdict from scored vulnerabilities and policy thresholds."""
    if not scored:
        return Decision(Verdict.ALLOW, 0, [], "No known vulnerabilities found.")

    # Worst-case wins: the project verdict is driven by its single highest
    # contextual score. Averaging would let one critical finding hide behind
    # many low ones, which is the opposite of what a security gate must do.
    blocking = [v for v in scored if v.contextual_score >= policy.block_threshold]
    warning = [
        v for v in scored
        if policy.warn_threshold <= v.contextual_score < policy.block_threshold
    ]

    if blocking:
        # Exit code 1 signals failure to the CI runner (FR09). Sorted highest
        # first so the most urgent item is the first thing a developer reads.
        return Decision(
            verdict=Verdict.BLOCK,
            exit_code=1,
            contributing=sorted(blocking, key=lambda v: -v.contextual_score),
            summary=(
                f"{len(blocking)} dependency finding(s) at or above the block "
                f"threshold of {policy.block_threshold}."
            ),
        )

    if warning:
        # Exit code 0: a warning must not fail the build. Warning and blocking
        # are separated deliberately — conflating them would make the gate
        # unusable, because every advisory would halt delivery.
        return Decision(
            verdict=Verdict.WARN,
            exit_code=0,
            contributing=sorted(warning, key=lambda v: -v.contextual_score),
            summary=(
                f"{len(warning)} finding(s) between the warn threshold of "
                f"{policy.warn_threshold} and the block threshold."
            ),
        )

    return Decision(
        verdict=Verdict.ALLOW,
        exit_code=0,
        contributing=[],
        summary=f"All {len(scored)} finding(s) below the warn threshold.",
    )