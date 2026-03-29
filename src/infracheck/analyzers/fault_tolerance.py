from infracheck.analyzers.scoring import score_results
from infracheck.models import CategoryScore
from infracheck.rules.fault_tolerance import (
    check_dynamodb_pitr,
    check_lambda_dlq,
    check_rds_backup_retention,
    check_rds_deletion_protection,
    check_rds_multi_az,
    check_sqs_dlq,
)

CATEGORY = "fault_tolerance"


def run(resources: dict[str, list[dict]]) -> CategoryScore:
    """Run all fault tolerance rules against the parsed resources."""
    results = [
        *check_sqs_dlq(resources),
        *check_rds_multi_az(resources),
        *check_rds_backup_retention(resources),
        *check_rds_deletion_protection(resources),
        *check_lambda_dlq(resources),
        *check_dynamodb_pitr(resources),
    ]

    return CategoryScore(
        name=CATEGORY,
        score=score_results(results),
        findings=results,
    )
