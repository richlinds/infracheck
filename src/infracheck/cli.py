import os
import sys

import typer

from infracheck.analyzers.engine import run
from infracheck.output.formatter import print_report
from infracheck.parsers.terraform import parse_directory


def analyze(
    path: str = typer.Argument(
        default=None,
        help="Path to the directory containing Terraform files.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Use Claude to add plain-language explanations to each failing check.",
    ),
) -> None:
    """Analyze a Terraform directory and score it across four categories."""
    # Resolve path: CLI argument → INFRACHECK_PATH env var → ./infra
    resolved_path = path or os.getenv("INFRACHECK_PATH", "./infra")

    if not os.path.isdir(resolved_path):
        typer.echo(
            typer.style(f"Error: '{resolved_path}' is not a directory.", fg="red"),
            err=True,
        )
        raise typer.Exit(code=1)

    typer.echo(f"Analyzing {resolved_path}...")

    resources = parse_directory(resolved_path)

    if not resources:
        typer.echo(
            typer.style("No Terraform resources found.", fg="yellow"),
            err=True,
        )
        raise typer.Exit(code=1)

    report = run(path=resolved_path, resources=resources)

    if explain:
        if not os.getenv("ANTHROPIC_API_KEY"):
            typer.echo(
                typer.style(
                    "Error: ANTHROPIC_API_KEY is not set. Export it to use --explain.",
                    fg="red",
                ),
                err=True,
            )
            raise typer.Exit(code=1)
        typer.echo("Generating explanations...")
        from infracheck.explainer import explain_findings

        report = explain_findings(report)

    print_report(report)

    # Exit with a non-zero code if the overall score is below 5
    if report.overall_score < 5:
        sys.exit(2)


def main() -> None:
    typer.run(analyze)
