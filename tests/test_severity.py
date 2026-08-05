from verdikt.severity import extract_base_score


def test_extracts_cvss_v3_base_score():
    """TC03: a CVSS v3 vector is parsed into a numeric base score.

    Vector chosen because its published base score is 9.8 — verifiable
    against the CVSS v3.1 specification independently of this code.
    """
    record = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ]
    }

    score, reason = extract_base_score(record)

    assert score == 9.8
    assert reason is None


def test_returns_float_not_decimal():
    """The cvss library returns Decimal; conversion happens at this boundary.

    Regression test for a real bug: Decimal * float raises TypeError, which
    crashed the scoring engine on first contact with live OSV data. Converting
    here means every downstream module handles one consistent numeric type.
    """
    record = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ]
    }

    score, _ = extract_base_score(record)

    assert isinstance(score, float)
    # Proves it can participate in arithmetic with other floats without error.
    assert score * 0.5 == 4.9


def test_selects_highest_of_multiple_v3_vectors():
    """Worst-case selection, consistent with the rest of the tool."""
    record = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        ]
    }

    score, _ = extract_base_score(record)

    assert score == 9.8


def test_rejects_cvss_v4_as_unsupported():
    """TC04: a non-v3 vector is not silently misread as v3.

    OSV added CVSS_V4 support in 2024. Parsing a v4 vector with a v3 parser
    would produce a wrong number, which is worse than producing none — the
    tool would report false precision.
    """
    record = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}

    score, reason = extract_base_score(record)

    assert score is None
    assert "CVSS_V4" in reason


def test_missing_severity_returns_unscored_not_zero():
    """No severity data yields None, never a guessed number.

    Returning 0.0 would claim the vulnerability is harmless. Returning a value
    derived from a qualitative label like "HIGH" would be an invented number
    with no defensible origin. None forces the caller to handle uncertainty
    explicitly.
    """
    score, reason = extract_base_score({})

    assert score is None
    assert reason is not None


def test_unparseable_vector_returns_none():
    """A malformed vector is caught rather than crashing the scan."""
    record = {"severity": [{"type": "CVSS_V3", "score": "not-a-valid-vector"}]}

    score, reason = extract_base_score(record)

    assert score is None