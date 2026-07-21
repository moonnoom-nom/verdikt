from pathlib import Path
from typing import NamedTuple


class Dependency(NamedTuple):
    name: str
    version: str


class MalformedLine(NamedTuple):
    line_number: int
    content: str


def parse_requirements(filepath: str | Path) -> tuple[list[Dependency], list[MalformedLine]]:
    """Parse a requirements.txt file into valid dependencies and malformed lines."""
    parsed: list[Dependency] = []
    malformed: list[MalformedLine] = []

    for line_number, raw_line in enumerate(Path(filepath).read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            parsed.append(Dependency(name.strip(), version.strip()))
        else:
            malformed.append(MalformedLine(line_number, line))

    return parsed, malformed