from infracheck.analyzers.scoring import score_results
from infracheck.models import CategoryScore
from infracheck.rules.observability import (
    check_alb_access_logging,
    check_cloudtrail_cloudwatch_integration,
    check_cloudwatch_alarms_exist,
    check_lambda_log_groups,
    check_lambda_xray_tracing,
    check_log_group_retention,
    check_vpc_flow_logs,
)

CATEGORY = "observability"


def run(resources: dict[str, list[dict]]) -> CategoryScore:
    """Run all observability rules against the parsed resources."""
    results = [
        *check_cloudwatch_alarms_exist(resources),
        *check_lambda_log_groups(resources),
        *check_lambda_xray_tracing(resources),
        *check_log_group_retention(resources),
        *check_alb_access_logging(resources),
        *check_cloudtrail_cloudwatch_integration(resources),
        *check_vpc_flow_logs(resources),
    ]

    return CategoryScore(
        name=CATEGORY,
        score=score_results(results),
        findings=results,
    )
