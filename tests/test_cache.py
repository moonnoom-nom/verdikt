from verdikt import cache


def test_cache_miss_returns_none(tmp_path, monkeypatch):
    """An uncached package returns None, distinct from an empty result.

    monkeypatch redirects CACHE_DIR to a temp folder so tests never touch
    the real .cache directory — otherwise tests would pollute development
    data and results would depend on scan history.
    """
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path)

    assert cache.read_cache("nonexistent", "1.0.0") is None


def test_write_then_read_returns_same_data(tmp_path, monkeypatch):
    """TC16: cached data survives a write/read round trip."""
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path)
    vulns = [{"id": "GHSA-test", "summary": "example"}]

    cache.write_cache("pkg", "1.0.0", vulns)

    assert cache.read_cache("pkg", "1.0.0") == vulns


def test_cache_key_includes_version(tmp_path, monkeypatch):
    """TC17: different versions of one package cache separately.

    Caching by package name alone would return one version's vulnerabilities
    for another — a correctness bug that would silently produce wrong scores
    for every project pinning a different version.
    """
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path)

    cache.write_cache("pkg", "1.0.0", [{"id": "OLD-VULN"}])
    cache.write_cache("pkg", "2.0.0", [{"id": "NEW-VULN"}])

    assert cache.read_cache("pkg", "1.0.0") == [{"id": "OLD-VULN"}]
    assert cache.read_cache("pkg", "2.0.0") == [{"id": "NEW-VULN"}]


def test_empty_result_caches_as_empty_not_missing(tmp_path, monkeypatch):
    """A clean package caches as [], which must not read back as None.

    This is why the fetcher uses `is not None` rather than truthiness — an
    empty list is falsy, so `if cached:` would treat a cached clean package
    as a cache miss and re-fetch it on every single run.
    """
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path)

    cache.write_cache("clean-pkg", "1.0.0", [])

    assert cache.read_cache("clean-pkg", "1.0.0") == []
    assert cache.read_cache("clean-pkg", "1.0.0") is not None