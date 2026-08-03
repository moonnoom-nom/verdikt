import json
from pathlib import Path
from typing import NamedTuple

# Sets rather than lists: membership checks are constant-time, and these three
# constants ARE the schema — the entire allowed vocabulary visible in one place.
VALID_TIERS = {"development", "staging", "production"}
VALID_EXPOSURE = {"air-gapped", "internal", "internet-facing"}
VALID_SENSITIVITY = {"public", "internal", "confidential"}


class PolicyError(ValueError):
    """Raised when a policy file is missing fields or contains invalid values."""
    # Inherits ValueError so callers can catch policy problems specifically,
    # while code unaware of this type still handles it sensibly.


class Policy(NamedTuple):
    # Thresholds are nested in the JSON for human readability but flattened here
    # because the scoring engine consumes them directly. File format optimised
    # for humans; object shape optimised for code.
    environment_tier: str
    network_exposure: str
    data_sensitivity: str
    warn_threshold: float
    block_threshold: float


def _require(data: dict, field: str, allowed: set[str]) -> str:
    # Extracted because all three attributes need identical validation.
    # One implementation guarantees consistent error messages and makes
    # adding a fourth attribute a one-line change.
    if field not in data:
        raise PolicyError(f"Missing required field: '{field}'")
    value = data[field]
    if value not in allowed:
        # Error names the field AND its permitted values (FR05): the developer
        # reading this in a CI log cannot see the source code.
        raise PolicyError(
            f"Invalid value for '{field}': '{value}'. Allowed: {sorted(allowed)}"
        )
    return value


def load_policy(filepath: str | Path) -> Policy:
    """Load and validate a policy file, raising PolicyError on invalid input."""
    path = Path(filepath)
    if not path.exists():
        # Own exception type rather than letting FileNotFoundError escape:
        # every policy failure surfaces through one consistent channel.
        raise PolicyError(f"Policy file not found: {path}")

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        # "from exc" preserves the original traceback, so the underlying parse
        # detail survives while the caller sees a domain-specific error.
        raise PolicyError(f"Policy file is not valid JSON: {exc}") from exc

    thresholds = data.get("thresholds", {})  # default {} so a missing block gives a useful error, not KeyError
    if "warn" not in thresholds or "block" not in thresholds:
        raise PolicyError("Missing required field: 'thresholds.warn' and 'thresholds.block'")

    warn = float(thresholds["warn"])
    block = float(thresholds["block"])
    # Semantic validation, not just structural: a file can be valid JSON with
    # every field present and still be incoherent if warn sits above block.
    if warn >= block:
        raise PolicyError(f"warn threshold ({warn}) must be lower than block threshold ({block})")

    # Keyword arguments: with five fields, positional order makes silently
    # swapping two strings easy.
    return Policy(
        environment_tier=_require(data, "environment_tier", VALID_TIERS),
        network_exposure=_require(data, "network_exposure", VALID_EXPOSURE),
        data_sensitivity=_require(data, "data_sensitivity", VALID_SENSITIVITY),
        warn_threshold=warn,
        block_threshold=block,
    )