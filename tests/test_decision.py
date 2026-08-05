from verdikt.decision import decide, Verdict
from verdikt.policy import Policy
from verdikt.scoring import score_vulnerability, unscored


POLICY = Policy(
    environment_tier="production",
    network_exposure="internet-facing",
    data_sensitivity="confidential",
    warn_threshold=4.0,
    block_threshold=7.0,
)


def scored_at(base_score: float, vuln_id: str = "TEST"):
    """Helper: produce a finding with a known contextual score.

    MAX_CONTEXT weights are all 1.0, so contextual score equals base score —
    which means these tests can specify exact scores directly rather than
    reverse-engineering what base score produces a given contextual one.
    """
    return score_vulnerability(vuln_id, "pkg", "1.0", base_score, POLICY)


def test_empty_findings_allows():
    """A project with no known vulnerabilities passes."""
    decision = decide([], POLICY)

    assert decision.verdict == Verdict.ALLOW
    assert decision.exit_code == 0


def test_single_blocking_finding_blocks():
    """TC11: any finding at or above the block threshold fails the build."""
    decision = decide([scored_at(8.0)], POLICY)

    assert decision.verdict == Verdict.BLOCK
    assert decision.exit_code == 1


def test_score_exactly_at_threshold_blocks():
    """Boundary: the block threshold is inclusive.

    7.0 with block_threshold 7.0 must BLOCK, not WARN. This is where an
    off-by-one between >= and > hides — it would never show up testing 8.0.
    """
    decision = decide([scored_at(7.0)], POLICY)

    assert decision.verdict == Verdict.BLOCK


def test_score_just_below_threshold_warns():
    """Boundary: 6.9 sits below block, above warn."""
    decision = decide([scored_at(6.9)], POLICY)

    assert decision.verdict == Verdict.WARN
    assert decision.exit_code == 0


def test_warn_returns_exit_code_zero():
    """TC12: WARN must not fail the build.

    If a warning failed the build it would be indistinguishable from a block,
    and the three-verdict model would collapse into two.
    """
    decision = decide([scored_at(5.0)], POLICY)

    assert decision.verdict == Verdict.WARN
    assert decision.exit_code == 0


def test_worst_case_drives_verdict_not_average():
    """TC13: one critical finding blocks despite many low-scoring ones.

    The mean of these seven scores is well below the block threshold. If the
    engine averaged rather than taking worst-case, this would ALLOW — which
    is precisely the failure mode a security gate must not have.
    """
    findings = [scored_at(0.5, f"LOW-{i}") for i in range(6)]
    findings.append(scored_at(9.8, "CRITICAL-1"))

    decision = decide(findings, POLICY)

    assert decision.verdict == Verdict.BLOCK


def test_unscored_finding_forces_warn_not_allow():
    """TC14: an unscored finding is never silently allowed.

    "We could not determine severity" and "this is safe" must produce
    different outcomes, or the tool would hide its own uncertainty.
    """
    decision = decide([unscored("U-1", "pkg", "1.0", "no CVSS v3 vector")], POLICY)

    assert decision.verdict == Verdict.WARN
    assert decision.exit_code == 0


def test_unscored_finding_does_not_force_block():
    """An unknown severity is not treated as automatically critical either.

    Blocking on unknown would make the tool unusable — many real OSV records
    lack CVSS v3 vectors, so every scan would fail regardless of actual risk.
    """
    decision = decide([unscored("U-1", "pkg", "1.0", "no vector")], POLICY)

    assert decision.verdict != Verdict.BLOCK


def test_block_verdict_still_reports_warning_and_unscored_findings():
    """TC15: the transparency rule — BLOCK must not hide other findings.

    The verdict is worst-case, but the report is complete. A gate that says
    "BLOCK, 1 finding" while silently discarding warnings and unscored items
    misleads the developer about what actually needs review.
    """
    findings = [
        scored_at(9.0, "BLOCKING-1"),
        scored_at(5.0, "WARNING-1"),
        unscored("UNSCORED-1", "pkg", "1.0", "no vector"),
    ]

    decision = decide(findings, POLICY)

    assert decision.verdict == Verdict.BLOCK
    # All three must appear, not just the blocking one.
    assert len(decision.contributing) == 3
    reported_ids = {v.vulnerability_id for v in decision.contributing}
    assert reported_ids == {"BLOCKING-1", "WARNING-1", "UNSCORED-1"}


def test_blocking_findings_sorted_highest_first():
    """The most urgent item is the first thing a developer reads."""
    findings = [scored_at(7.2, "LOWER"), scored_at(9.5, "HIGHER")]

    decision = decide(findings, POLICY)

    assert decision.contributing[0].vulnerability_id == "HIGHER"