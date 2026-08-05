import json

import pytest

from verdikt.policy import load_policy, PolicyError


def write_policy(tmp_path, data: dict):
    """Helper: write a policy dict to a temp file and return its path.

    Extracted because every test needs this, and repeating it six times
    would make the tests harder to read than the code they're testing.
    """
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data))
    return path


VALID = {
    "environment_tier": "production",
    "network_exposure": "internet-facing",
    "data_sensitivity": "confidential",
    "thresholds": {"warn": 4.0, "block": 7.0},
}


def test_loads_valid_policy(tmp_path):
    """TC05: a well-formed policy file loads with all fields populated."""
    policy = load_policy(write_policy(tmp_path, VALID))

    assert policy.environment_tier == "production"
    assert policy.network_exposure == "internet-facing"
    assert policy.data_sensitivity == "confidential"
    # Thresholds are flattened from the nested JSON structure — this asserts
    # that transformation happened, not just that the file was read.
    assert policy.warn_threshold == 4.0
    assert policy.block_threshold == 7.0


def test_rejects_invalid_environment_tier(tmp_path):
    """TC06: an invalid value is rejected with an error naming the field."""
    bad = {**VALID, "environment_tier": "produciton"}  # deliberate typo

    with pytest.raises(PolicyError) as exc:
        load_policy(write_policy(tmp_path, bad))

    # The error must name the offending field and the bad value — FR05's
    # actual promise. Asserting on message content, not just that it raised,
    # because "an error occurred" is useless to a developer reading CI logs.
    assert "environment_tier" in str(exc.value)
    assert "produciton" in str(exc.value)


def test_rejects_missing_field(tmp_path):
    """A missing required field is caught, not silently defaulted."""
    incomplete = {k: v for k, v in VALID.items() if k != "network_exposure"}

    with pytest.raises(PolicyError) as exc:
        load_policy(write_policy(tmp_path, incomplete))

    assert "network_exposure" in str(exc.value)


def test_rejects_incoherent_thresholds(tmp_path):
    """Semantic validation: warn must be below block, not merely present."""
    # This is the test that proves validation goes beyond structure. The file
    # below is valid JSON with every required field — only its logic is wrong.
    incoherent = {**VALID, "thresholds": {"warn": 8.0, "block": 3.0}}

    with pytest.raises(PolicyError):
        load_policy(write_policy(tmp_path, incoherent))


def test_rejects_malformed_json(tmp_path):
    """Broken JSON surfaces as PolicyError, not a raw JSONDecodeError."""
    path = tmp_path / "policy.json"
    path.write_text("{ this is not valid json")

    with pytest.raises(PolicyError):
        load_policy(path)


def test_rejects_missing_file(tmp_path):
    """A missing file fails through the same channel as every other policy problem."""
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "does-not-exist.json")