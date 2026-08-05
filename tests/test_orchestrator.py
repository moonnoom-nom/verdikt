from unittest.mock import patch

from verdikt.orchestrator import scan_project
from verdikt.parser import Dependency
from verdikt.policy import Policy
from verdikt.decision import Verdict


HIGH_CONTEXT = Policy(
    environment_tier="production",
    network_exposure="internet-facing",
    data_sensitivity="confidential",
    warn_threshold=4.0,
    block_threshold=7.0,
)

LOW_CONTEXT = Policy(
    environment_tier="development",
    network_exposure="air-gapped",
    data_sensitivity="public",
    warn_threshold=4.0,
    block_threshold=7.0,
)

# A single critical vulnerability record, reused across tests. Base score 9.8
# under maximum context, but attenuated to 2.35 under minimum context — which
# straddles the 7.0 block threshold and so produces different verdicts.
CRITICAL_RECORD = [
    {
        "id": "GHSA-test-critical",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
    }
]


def test_same_vulnerability_different_verdict_by_context():
    """The central claim of the project, tested end to end.

    Identical dependency, identical vulnerability data, identical thresholds.
    Only the three contextual attributes differ. If this test ever fails, the
    project's core hypothesis is not being demonstrated by the artefact.
    """
    deps = [Dependency("pkg", "1.0.0")]

    with patch("verdikt.orchestrator.fetch_vulnerabilities", return_value=CRITICAL_RECORD):
        high = scan_project(deps, HIGH_CONTEXT)
        low = scan_project(deps, LOW_CONTEXT)

    assert high.verdict == Verdict.BLOCK
    assert low.verdict != Verdict.BLOCK


def test_aggregates_across_multiple_dependencies():
    """One risky dependency among several drives the whole project verdict.

    A CI gate protects the project, not one package — so the worst finding
    anywhere must determine the outcome, regardless of how many clean
    dependencies surround it.
    """
    deps = [
        Dependency("clean-one", "1.0.0"),
        Dependency("risky", "1.0.0"),
        Dependency("clean-two", "1.0.0"),
    ]

    def fake_fetch(name, version):
        # Only the middle dependency carries a vulnerability.
        return CRITICAL_RECORD if name == "risky" else []

    with patch("verdikt.orchestrator.fetch_vulnerabilities", side_effect=fake_fetch):
        decision = scan_project(deps, HIGH_CONTEXT)

    assert decision.verdict == Verdict.BLOCK


def test_project_with_no_vulnerabilities_allows():
    """A clean project passes the gate."""
    deps = [Dependency("clean", "1.0.0")]

    with patch("verdikt.orchestrator.fetch_vulnerabilities", return_value=[]):
        decision = scan_project(deps, HIGH_CONTEXT)

    assert decision.verdict == Verdict.ALLOW
    assert decision.exit_code == 0