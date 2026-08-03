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
#
# It also matches the standard: CVSS base metrics are calculated assuming
# reasonable worst-case environmental conditions, so downward adjustment toward
# a known deployment is the operation the specification anticipates.

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
    base_score: float
    contextual_score: float
    band: str
    # Human-readable explanation carried with the result rather than regenerated
    # at print time, so the reasoning survives into the JSON report unchanged.
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
) -> ScoredVulnerability:
    """Apply policy attenuation to a CVSS base score."""
    env = ENVIRONMENT_WEIGHTS[policy.environment_tier]
    exposure = EXPOSURE_WEIGHTS[policy.network_exposure]
    sensitivity = SENSITIVITY_WEIGHTS[policy.data_sensitivity]

    # Multiplicative rather than additive: the factors compound. A vulnerability
    # that is both internet-facing and in production is riskier than the sum of
    # those conditions, because an attacker needs reachability AND a target
    # worth reaching. Addition would treat them as independent.
    contextual = base_score * env * exposure * sensitivity

    # Round to one decimal to match CVSS presentation. min() is a safety guard
    # only — under attenuation the product can never exceed base_score, so if
    # this ever triggers, a weight above 1.0 has been introduced by mistake.
    contextual = round(min(contextual, base_score), 1)

    rationale = (
        f"CVSS {base_score} x env {env} x exposure {exposure} "
        f"x data {sensitivity} = {contextual}"
    )

    return ScoredVulnerability(
        vulnerability_id=vulnerability_id,
        package=package,
        version=version,
        base_score=base_score,
        contextual_score=contextual,
        band=classify(contextual),
        rationale=rationale,
    )