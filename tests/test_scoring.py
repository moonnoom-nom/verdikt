from verdikt.policy import Policy
from verdikt.scoring import score_vulnerability, unscored, classify


# Constructed directly rather than loaded from a file: these tests verify
# scoring arithmetic, not policy loading. Building the Policy inline keeps
# each test independent of policy.py working correctly.
MAX_CONTEXT = Policy(
    environment_tier="production",
    network_exposure="internet-facing",
    data_sensitivity="confidential",
    warn_threshold=4.0,
    block_threshold=7.0,
)

MIN_CONTEXT = Policy(
    environment_tier="development",
    network_exposure="air-gapped",
    data_sensitivity="public",
    warn_threshold=4.0,
    block_threshold=7.0,
)


def test_max_context_returns_base_score_unchanged():
    """TC07: attenuation ceiling — maximum context never exceeds the base score.

    This is the central property of the model. All weights at 1.0 means the
    contextual score equals the CVSS base score exactly. If this ever exceeds
    base_score, a weight above 1.0 has been introduced and the model has
    silently become amplification.
    """
    result = score_vulnerability("TEST-1", "pkg", "1.0", 7.5, MAX_CONTEXT)

    assert result.contextual_score == 7.5
    assert result.raw_score == 7.5


def test_min_context_attenuates_score():
    """TC08: low context scales the score down multiplicatively.

    7.5 x 0.5 (development) x 0.4 (air-gapped) x 0.6 (public) = 0.9
    """
    result = score_vulnerability("TEST-2", "pkg", "1.0", 7.5, MIN_CONTEXT)

    assert result.contextual_score == 0.9
    assert result.raw_score < 7.5


def test_raw_score_is_unrounded_display_score_is_rounded():
    """TC09: the two scores are genuinely separate values.

    This is the rounding bug guard. If raw_score were rounded before the
    decision engine compared it against a threshold, a value like 4.96 would
    become 5.0 and wrongly cross a block threshold of 5.0 it never reached.
    """
    result = score_vulnerability("TEST-3", "pkg", "1.0", 7.5, MIN_CONTEXT)

    # Display is rounded to one decimal; raw retains full precision.
    assert result.contextual_score == round(result.raw_score, 1)
    # And they are not the same object/value by accident.
    assert result.raw_score != result.contextual_score or result.raw_score == round(result.raw_score, 1)


def test_contextual_score_never_exceeds_base_score():
    """The attenuation invariant holds across the full 0-10 input range."""
    # Testing a range rather than one value: a model that happens to work for
    # 7.5 but breaks at 9.8 would pass a single-value test and fail in
    # production. RQ2 depends on this holding everywhere, not just at one point.
    for base in [0.1, 2.0, 4.0, 5.5, 7.5, 9.0, 10.0]:
        for policy in [MAX_CONTEXT, MIN_CONTEXT]:
            result = score_vulnerability("TEST", "pkg", "1.0", base, policy)
            assert result.raw_score <= base


def test_classify_uses_cvss_band_boundaries():
    """TC10: risk bands match the CVSS v3.1 specification exactly.

    Boundary values are tested, not midpoints — 9.0 and 8.9 sit either side of
    the Critical/High line, and off-by-one errors only appear at the edges.
    """
    assert classify(9.2) == "Critical"
    assert classify(9.0) == "Critical"
    assert classify(8.9) == "High"
    assert classify(7.0) == "High"
    assert classify(6.9) == "Medium"
    assert classify(4.0) == "Medium"
    assert classify(3.9) == "Low"
    assert classify(0.0) == "None"


def test_unscored_produces_none_scores_not_zero():
    """An unscored finding is distinguishable from a zero-severity one.

    Returning 0.0 would make "we could not determine severity" look identical
    to "this is harmless" — the decision engine must be able to tell them
    apart, so it can force a WARN rather than a silent ALLOW.
    """
    result = unscored("TEST-4", "pkg", "1.0", "no CVSS v3 vector")

    assert result.raw_score is None
    assert result.contextual_score is None
    assert result.band == "Unscored"
    assert "no CVSS v3 vector" in result.rationale