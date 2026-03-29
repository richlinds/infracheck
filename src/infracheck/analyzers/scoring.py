from infracheck.models import RuleResult

# High severity failures cost more than medium, medium more than low.
# This ensures a single critical misconfiguration meaningfully lowers the score.
SEVERITY_WEIGHTS = {"high": 3, "medium": 2, "low": 1}


def score_results(results: list[RuleResult]) -> int:
    """Calculate a 0–10 score from a list of rule results using severity weighting.

    A category where every check passes scores 10. A category with no checks also
    scores 10. Failures are weighted by severity so a high-severity failure costs
    more than a low-severity one.
    """
    if not results:
        return 10

    total_weight = sum(SEVERITY_WEIGHTS.get(result.severity, 1) for result in results)
    fail_weight = sum(
        SEVERITY_WEIGHTS.get(result.severity, 1) for result in results if not result.passed
    )

    if total_weight == 0:
        return 10

    pass_ratio = 1.0 - (fail_weight / total_weight)
    return round(pass_ratio * 10)
