"""Terminal presentation layer.

Separated from decision.py deliberately: the decision engine determines the
verdict, this module only presents it. Mixing them would mean the gating logic
carried formatting concerns, and the verdict could not be tested without
capturing printed output.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from verdikt.decision import Decision, Verdict
from verdikt.policy import Policy

console = Console()

# Colour carries meaning here, not decoration: red/amber/green is the
# universally understood severity convention, so the verdict is legible
# before any text is read.
VERDICT_STYLES = {
    Verdict.BLOCK: ("red", "⛔", "DEPLOYMENT REJECTED"),
    Verdict.WARN: ("yellow", "⚠", "PROCEED WITH CAUTION"),
    Verdict.ALLOW: ("green", "✅", "DEPLOYMENT APPROVED"),
}


def render(decision: Decision, policy: Policy, dependency_count: int) -> None:
    """Print a verdict banner, the active policy, and contributing findings."""
    colour, icon, subtitle = VERDICT_STYLES[decision.verdict]

    console.print()
    console.print(
        Panel(
            f"[bold {colour}]{icon}  {decision.verdict.value}[/]\n[{colour}]{subtitle}[/]",
            border_style=colour,
            expand=False,
        )
    )

    # The policy is printed alongside the verdict because the verdict is
    # meaningless without it — the same findings under a different policy
    # produce a different outcome, and hiding that would obscure the tool's
    # entire contribution.
    console.print(
        f"[dim]Policy:[/] [bold]{policy.environment_tier}[/] · "
        f"[bold]{policy.network_exposure}[/] · "
        f"[bold]{policy.data_sensitivity}[/]"
    )
    console.print(
        f"[dim]Thresholds:[/] warn {policy.warn_threshold} · block {policy.block_threshold}"
    )
    console.print(f"[dim]Scanned:[/] {dependency_count} dependencies")
    console.print()
    console.print(f"[{colour}]{decision.summary}[/]")

    if not decision.contributing:
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Package")
    table.add_column("Vulnerability")
    table.add_column("Base", justify="right")
    table.add_column("Context", justify="right")
    table.add_column("Band")

    # Only the top findings are tabulated — a 400-finding scan is unreadable
    # in a terminal, and the developer needs the worst items, not all of them.
    for v in decision.contributing[:15]:
        band_colour = {
            "Critical": "bright_red",
            "High": "red",
            "Medium": "yellow",
            "Low": "green",
            "Unscored": "dim",
        }.get(v.band, "white")

        table.add_row(
            f"{v.package} {v.version}",
            v.vulnerability_id,
            str(v.base_score) if v.base_score is not None else "—",
            str(v.contextual_score) if v.contextual_score is not None else "—",
            f"[{band_colour}]{v.band}[/]",
        )

    console.print()
    console.print(table)

    remaining = len(decision.contributing) - 15
    if remaining > 0:
        console.print(f"[dim]... and {remaining} further findings[/]")