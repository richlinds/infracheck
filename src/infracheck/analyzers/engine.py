from infracheck.analyzers import fault_tolerance, observability, scalability, security
from infracheck.models import Report

# All category analyzers. Add a new module here to include it in every report.
ANALYZERS = [fault_tolerance, scalability, security, observability]


def run(path: str, resources: dict[str, list[dict]]) -> Report:
    """Run all category analyzers and return a scored report.

    Each analyzer receives the full resource map and returns a CategoryScore.
    The overall score is the average of all category scores, rounded to the
    nearest integer.
    """
    categories = [analyzer.run(resources) for analyzer in ANALYZERS]
    overall_score = round(sum(category.score for category in categories) / len(categories))

    return Report(
        path=path,
        categories=categories,
        overall_score=overall_score,
    )
