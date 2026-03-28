from infracheck.models import RuleResult

CATEGORY = "fault_tolerance"


def check_sqs_dlq(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """Every SQS queue should have a dead-letter queue configured."""
    results = []

    for queue in resources.get("aws_sqs_queue", []):
        has_dlq = "redrive_policy" in queue
        results.append(
            RuleResult(
                rule_id="sqs_dlq_configured",
                category=CATEGORY,
                severity="high",
                passed=has_dlq,
                message="SQS queue has a dead-letter queue configured"
                if has_dlq
                else "SQS queue is missing a dead-letter queue — failed messages will be lost",
                resource=queue["_name"],
            )
        )

    return results


def check_rds_multi_az(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """RDS instances should have Multi-AZ enabled for failover."""
    results = []

    for instance in resources.get("aws_db_instance", []):
        is_multi_az = instance.get("multi_az", False)
        results.append(
            RuleResult(
                rule_id="rds_multi_az_enabled",
                category=CATEGORY,
                severity="high",
                passed=is_multi_az,
                message="RDS instance has Multi-AZ enabled"
                if is_multi_az
                else "RDS instance does not have Multi-AZ enabled — no automatic failover",
                resource=instance["_name"],
            )
        )

    return results


def check_rds_backup_retention(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """RDS instances should retain backups for at least 7 days."""
    results = []
    minimum_retention_days = 7

    for instance in resources.get("aws_db_instance", []):
        retention_days = instance.get("backup_retention_period", 0)
        has_sufficient_retention = retention_days >= minimum_retention_days
        results.append(
            RuleResult(
                rule_id="rds_backup_retention",
                category=CATEGORY,
                severity="medium",
                passed=has_sufficient_retention,
                message=(
                    f"RDS instance retains backups for {retention_days} days"
                    if has_sufficient_retention
                    else f"RDS instance backup retention is {retention_days} days"
                    f" — recommended minimum is {minimum_retention_days}"
                ),
                resource=instance["_name"],
            )
        )

    return results
