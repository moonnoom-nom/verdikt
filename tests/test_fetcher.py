from unittest.mock import patch

from verdikt import fetcher


def test_returns_empty_list_when_osv_reports_no_vulns():
    """A clean package yields [], not None or a crash.

    OSV omits the "vulns" key entirely for clean packages rather than
    returning an empty list — so .get("vulns", []) is doing real work here,
    not defensive padding. Without it this would raise KeyError on every
    healthy dependency.
    """
    # patch replaces requests.post for this test only, so no network call
    # happens — tests must not depend on OSV being reachable, or they'd fail
    # offline and in CI for reasons unrelated to the code.
    with patch("verdikt.fetcher.requests.post") as mock_post:
        mock_post.return_value.json.return_value = {}
        mock_post.return_value.raise_for_status.return_value = None

        result = fetcher.fetch_vulnerabilities("clean-pkg", "1.0.0", use_cache=False)

    assert result == []


def test_returns_vulns_when_present():
    """Vulnerability records pass through unmodified."""
    fake_vulns = [{"id": "GHSA-test"}]

    with patch("verdikt.fetcher.requests.post") as mock_post:
        mock_post.return_value.json.return_value = {"vulns": fake_vulns}
        mock_post.return_value.raise_for_status.return_value = None

        result = fetcher.fetch_vulnerabilities("pkg", "1.0.0", use_cache=False)

    assert result == fake_vulns


def test_sends_pypi_ecosystem_in_payload():
    """The ecosystem field must be PyPI, not left to OSV to guess.

    Package names collide across ecosystems — an npm package sharing a name
    with a PyPI one would return the wrong vulnerabilities entirely.
    """
    with patch("verdikt.fetcher.requests.post") as mock_post:
        mock_post.return_value.json.return_value = {}
        mock_post.return_value.raise_for_status.return_value = None

        fetcher.fetch_vulnerabilities("pkg", "1.0.0", use_cache=False)

    sent_payload = mock_post.call_args.kwargs["json"]
    assert sent_payload["package"]["ecosystem"] == "PyPI"