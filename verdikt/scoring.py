from typing import NamedTuple

from verdikt.policy import Policy

# Attenuation model: the CVSS base score is the worst-case ceiling, and context
# scales it DOWN toward the declared reality. Maximum context (production,
# internet-facing, confidential) equals 1.0, so a contextual score can never
# exceed the base score.
#
# This inverts the obvious approach of multiplying upward. Amplification would
# saturate: with multipliers above 1.0, any base score over ~4.2 would hit the
# 10.0 ceiling, collapsing Medium, High and Critical into an identical value and
# making RQ2 (which attribute matters most) unanswerable.

ENVIRONMENT_WEIGHTS = {
    "production": 1.0,
    "staging": 0.75,
    "development": 0.5,
}

EXPOSURE_WEIGHTS = {
    "internet-facing": 1.0,
    "internal": 0.7,
    "air-gapped": 0.4,
}

SENSITIVITY_WEIGHTS = {
    "confidential": 1.0,
    "internal": 0.8,
    "public": 0.6,
}


class ScoredVulnerability(NamedTuple):
    vulnerability_id: str
    package: str
    version: str
    # All three of these are Optional: None means "no CVSS v3 score could be
    # extracted," produced by unscored() below rather than by score_vulnerability().
    base_score: float | None
    contextual_score: float | None
    raw_score: float | None
    band: str
    rationale: str


def classify(score: float) -> str:
    """Map a score to a CVSS v3.1 severity band."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


def score_vulnerability(
    vulnerability_id: str,
    package: str,
    version: str,
    base_score: float,
    policy: Policy,
) -> ScoredVulnerability:
    """Apply policy attenuation to a CVSS base score."""
    env = ENVIRONMENT_WEIGHTS[policy.environment_tier]
    exposure = EXPOSURE_WEIGHTS[policy.network_exposure]
    sensitivity = SENSITIVITY_WEIGHTS[policy.data_sensitivity]

    # raw_score is unrounded and is what decision.py must compare against
    # thresholds. Rounding first would let 4.96 become 5.0 and wrongly cross
    # a block threshold of 5.0 that it never actually reached.
    raw_score = min(base_score * env * exposure * sensitivity, base_score)
    display_score = round(raw_score, 1)

    rationale = (
        f"CVSS {base_score} x env {env} x exposure {exposure} "
        f"x data {sensitivity} = {display_score}"
    )

    return ScoredVulnerability(
        vulnerability_id=vulnerability_id,
        package=package,
        version=version,
        base_score=base_score,
        contextual_score=display_score,
        raw_score=raw_score,
        band=classify(raw_score),
        rationale=rationale,
    )


def unscored(vulnerability_id: str, package: str, version: str, reason: str) -> ScoredVulnerability:
    """Placeholder result for a vulnerability with no usable CVSS v3 score.

    Returned as a first-class result rather than dropped, so the finding
    still surfaces to the developer and Chapter 7 can report how often
    this happened during evaluation.
    """
    return ScoredVulnerability(
        vulnerability_id=vulnerability_id,
        package=package,
        version=version,
        base_score=None,
        contextual_score=None,
        raw_score=None,
        band="Unscored",
        rationale=reason,
    )