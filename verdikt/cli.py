import sys

from verdikt.parser import parse_requirements
from verdikt.policy import load_policy, PolicyError
from verdikt.orchestrator import scan_project


def main() -> int:
    """Entry point for CI: scan requirements.txt against policy.json, exit
    with the code decide() produces. This is deliberately separate from
    run.py, which prints multiple demo scenarios for development — a CI
    gate should run exactly one real scan and exit accordingly, not narrate.
    """
    try:
        policy = load_policy("policy.json")
    except PolicyError as exc:
        # A broken policy must fail loudly and distinctly from a scan finding
        # something wrong — "the tool is misconfigured" and "the project is
        # risky" are different problems and must produce different signals.
        print(f"Policy error: {exc}", file=sys.stderr)
        return 2

    deps, malformed = parse_requirements("examples/requirements-vulnerable.txt")
    if malformed:
        for line_number, content in malformed:
            print(f"Warning: could not parse line {line_number}: {content}")

    decision = scan_project(deps, policy)
    from verdikt.reporter import render
    render(decision, policy, len(deps))

    return decision.exit_code


if __name__ == "__main__":
    sys.exit(main())