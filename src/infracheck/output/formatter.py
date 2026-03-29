import typer

from infracheck.models import Report

# Score thresholds for colour coding
SCORE_GOOD = 8
SCORE_WARN = 5

# Severity colours
SEVERITY_COLOURS = {
    "high": "red",
    "medium": "yellow",
    "low": "blue",
}

# Category display names
CATEGORY_LABELS = {
    "fault_tolerance": "Fault Tolerance",
    "scalability": "Scalability",
    "security": "Security",
    "observability": "Observability",
}


def _score_colour(score: int) -> str:
    if score >= SCORE_GOOD:
        return "green"
    if score >= SCORE_WARN:
        return "yellow"
    return "red"


def print_report(report: Report) -> None:
    """Print a formatted analysis report to the terminal."""
    typer.echo()
    typer.echo(typer.style("infracheck", bold=True) + f"  {report.path}")
    typer.echo("-" * 50)

    for category in report.categories:
        label = CATEGORY_LABELS.get(category.name, category.name.replace("_", " ").title())
        score_str = typer.style(str(category.score), fg=_score_colour(category.score), bold=True)
        typer.echo(f"\n  {label:<20} {score_str}/10")

        failures = [finding for finding in category.findings if not finding.passed]
        if not failures:
            typer.echo("  " + typer.style("  All checks passed", fg="green"))
            continue

        for finding in failures:
            colour = SEVERITY_COLOURS.get(finding.severity, "white")
            severity_tag = typer.style(f"[{finding.severity}]", fg=colour)
            resource_tag = f" ({finding.resource})" if finding.resource else ""
            typer.echo(f"    {severity_tag} {finding.message}{resource_tag}")

    typer.echo()
    typer.echo("-" * 50)
    overall_str = typer.style(
        str(report.overall_score), fg=_score_colour(report.overall_score), bold=True
    )
    typer.echo(f"  Overall score  {overall_str}/10")
    typer.echo()
