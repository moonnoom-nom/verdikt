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


class WeightConfiguration(NamedTuple):
    """A complete set of attenuation weights.

    Extracted into a passable object so the sensitivity analysis can vary
    weights without mutating module-level state. Mutating globals would make
    the analysis order-dependent and impossible to reason about.
    """
    environment: dict[str, float]
    exposure: dict[str, float]
    sensitivity: dict[str, float]


# The configuration used throughout the main evaluation.
DEFAULT_WEIGHTS = WeightConfiguration(
    environment=ENVIRONMENT_WEIGHTS,
    exposure=EXPOSURE_WEIGHTS,
    sensitivity=SENSITIVITY_WEIGHTS,
)


class ScoredVulnerability(NamedTuple):
    vulnerability_id: str
    package: str
    version: str
    # All three are Optional: None means no CVSS v3 score could be extracted,
    # produced by unscored() rather than score_vulnerability().
    base_score: float | None
    contextual_score: float | None
    raw_score: float | None
    band: str
    rationale: str


def classify(score: float) -> str:
    """Map a score to a CVSS v3.1 severity band."""
    # Boundaries taken from the CVSS v3.1 specification rather than invented,
    # so contextual scores remain directly comparable with published base scores.
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
    weights: WeightConfiguration = DEFAULT_WEIGHTS,
) -> ScoredVulnerability:
    """Apply policy attenuation to a CVSS base score."""
    # Weights default to DEFAULT_WEIGHTS so every existing caller keeps working
    # unchanged; only the sensitivity analysis passes alternatives.
    env = weights.environment[policy.environment_tier]
    exposure = weights.exposure[policy.network_exposure]
    sensitivity = weights.sensitivity[policy.data_sensitivity]

    # Multiplicative rather than additive: the factors compound. A vulnerability
    # that is both internet-facing and in production is riskier than the sum of
    # those conditions, because an attacker needs reachability AND a target
    # worth reaching.
    #
    # raw_score is unrounded and is what decision.py compares against
    # thresholds. Rounding first would let 4.96 become 5.0 and wrongly cross
    # a block threshold of 5.0 it never actually reached.
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

    Returned as a first-class result rather than dropped, so the finding still
    surfaces to the developer and Chapter 7 can report how often this happened.
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