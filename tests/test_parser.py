from verdikt.parser import parse_requirements, Dependency


def test_parses_pinned_dependencies(tmp_path):
    """TC01: parser extracts name and version from every pinned line."""
    # tmp_path is a pytest fixture: a real temporary directory, deleted after
    # the test. Using it rather than a committed fixture file means each test
    # controls its own input exactly, and no test can break another by
    # sharing state through a file on disk.
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.19.0\nflask==0.12.2\n")

    parsed, malformed = parse_requirements(req_file)

    assert len(parsed) == 2
    assert parsed[0] == Dependency("requests", "2.19.0")
    assert malformed == []


def test_reports_malformed_lines_with_line_numbers(tmp_path):
    """TC02: unpinned lines are reported with line numbers, not silently dropped."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.19.0\nflask>=1.0\n")

    parsed, malformed = parse_requirements(req_file)

    assert len(parsed) == 1
    assert len(malformed) == 1
    # Must be line 2, not 1 — proves enumerate(start=1) is correct, so a
    # developer reading the CI log can find the actual offending line.
    assert malformed[0].line_number == 2


def test_skips_comments_and_blank_lines(tmp_path):
    """Comments and blanks are neither parsed nor reported as malformed."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("# a comment\n\nrequests==2.19.0\n")

    parsed, malformed = parse_requirements(req_file)

    assert len(parsed) == 1
    assert malformed == []