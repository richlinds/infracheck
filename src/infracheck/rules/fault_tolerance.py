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


def check_lambda_dlq(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """Lambda functions should have a dead-letter queue configured for failed async invocations."""
    results = []

    for function in resources.get("aws_lambda_function", []):
        dead_letter_config = function.get("dead_letter_config", {})
        # dead_letter_config may be a list due to hcl2 block parsing
        if isinstance(dead_letter_config, list):
            dead_letter_config = dead_letter_config[0] if dead_letter_config else {}
        has_dlq = bool(dead_letter_config.get("target_arn"))

        results.append(
            RuleResult(
                rule_id="lambda_dlq_configured",
                category=CATEGORY,
                severity="medium",
                passed=has_dlq,
                message="Lambda function has a dead-letter queue configured"
                if has_dlq
                else "Lambda function has no dead-letter queue — failed async invocations"
                " will be silently dropped",
                resource=function["_name"],
            )
        )

    return results


def check_dynamodb_pitr(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """DynamoDB tables should have point-in-time recovery enabled."""
    results = []

    for table in resources.get("aws_dynamodb_table", []):
        pitr = table.get("point_in_time_recovery", {})
        # point_in_time_recovery may be a list due to hcl2 block parsing
        if isinstance(pitr, list):
            pitr = pitr[0] if pitr else {}
        has_pitr = pitr.get("enabled", False)

        results.append(
            RuleResult(
                rule_id="dynamodb_pitr_enabled",
                category=CATEGORY,
                severity="medium",
                passed=has_pitr,
                message="DynamoDB table has point-in-time recovery enabled"
                if has_pitr
                else "DynamoDB table does not have point-in-time recovery enabled"
                " — data loss window is up to 24 hours",
                resource=table["_name"],
            )
        )

    return results


def check_rds_deletion_protection(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """RDS instances should have deletion protection enabled to prevent accidental data loss."""
    results = []

    for instance in resources.get("aws_db_instance", []):
        has_deletion_protection = instance.get("deletion_protection", False)

        results.append(
            RuleResult(
                rule_id="rds_deletion_protection",
                category=CATEGORY,
                severity="medium",
                passed=has_deletion_protection,
                message="RDS instance has deletion protection enabled"
                if has_deletion_protection
                else "RDS instance does not have deletion protection enabled"
                " — it can be deleted accidentally",
                resource=instance["_name"],
            )
        )

    return results
