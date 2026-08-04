from cvss import CVSS3


def extract_base_score(vulnerability: dict) -> tuple[float | None, str | None]:
    """Extract a CVSS v3 base score from a raw OSV vulnerability record.

    Returns (score, reason). score is None when no usable CVSS v3 score
    exists — the caller must not guess a number in that case, only report why.
    """
    entries = vulnerability.get("severity", [])

    # OSV makes top-level and per-package severity mutually exclusive
    # (ossf.github.io/osv-schema). Most PyPI/GHSA advisories describe one
    # package and use top-level severity, so checking only the top level
    # covers the common case. Per-package severity for multi-package
    # advisories is a documented scope boundary, not an oversight.
    v3_entries = [e for e in entries if e.get("type") == "CVSS_V3"]

    if not v3_entries:
        other_types = sorted({e.get("type") for e in entries if e.get("type")})
        if other_types:
            # e.g. only a CVSS_V4 vector was provided — real and increasingly
            # common since the schema added CVSS_V4 support in Jan 2024.
            return None, f"No CVSS v3 score; only found: {', '.join(other_types)}"
        return None, "No CVSS severity data provided by OSV for this record"

    scores = []
    for entry in v3_entries:
        try:
            scores.append(float(CVSS3(entry.get("score", "")).base_score))
        except Exception:
            # Catching broadly here rather than a specific exception class:
            # I haven't confirmed the exact exception name the installed
            # `cvss` version raises on a malformed vector. Skipping one bad
            # vector is a fair trade against crashing the whole scan on it.
            continue

    if not scores:
        return None, "CVSS v3 entry present but vector could not be parsed"

    # Worst-case again, consistent with the rest of the tool: if a record
    # carries multiple v3 vectors, use the highest.
    return max(scores), None