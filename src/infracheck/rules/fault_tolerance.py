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
                else "SQS queue is missing a dead-letter queue - failed messages will be lost",
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
                else "RDS instance does not have Multi-AZ enabled - no automatic failover",
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
                    f" - recommended minimum is {minimum_retention_days}"
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
                else "Lambda function has no dead-letter queue - failed async invocations"
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
                " - data loss window is up to 24 hours",
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
                " - it can be deleted accidentally",
                resource=instance["_name"],
            )
        )

    return results


def check_s3_versioning(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """S3 buckets should have versioning enabled to protect against accidental deletion."""
    results = []

    for versioning in resources.get("aws_s3_bucket_versioning", []):
        versioning_config = versioning.get("versioning_configuration", {})
        # versioning_configuration may be a list due to hcl2 block parsing
        if isinstance(versioning_config, list):
            versioning_config = versioning_config[0] if versioning_config else {}
        is_enabled = versioning_config.get("status", "") == "Enabled"

        results.append(
            RuleResult(
                rule_id="s3_versioning_enabled",
                category=CATEGORY,
                severity="medium",
                passed=is_enabled,
                message="S3 bucket has versioning enabled"
                if is_enabled
                else "S3 bucket does not have versioning enabled"
                " - objects cannot be recovered after deletion or overwrite",
                resource=versioning["_name"],
            )
        )

    return results


def check_ecs_min_healthy_percent(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ECS services should keep at least 50% of tasks running during deployments."""
    results = []
    minimum_healthy_percent = 50

    for service in resources.get("aws_ecs_service", []):
        min_healthy = service.get("deployment_minimum_healthy_percent", 100)
        is_sufficient = min_healthy >= minimum_healthy_percent

        results.append(
            RuleResult(
                rule_id="ecs_min_healthy_percent",
                category=CATEGORY,
                severity="high",
                passed=is_sufficient,
                message=f"ECS service keeps {min_healthy}% of tasks running during deployments"
                if is_sufficient
                else f"ECS service deployment_minimum_healthy_percent is {min_healthy}%"
                " - tasks may be fully stopped during deployments",
                resource=service["_name"],
            )
        )

    return results


def check_sns_topic_dlq(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """SNS topics should have a redrive policy to capture undeliverable messages."""
    results = []

    for topic in resources.get("aws_sns_topic", []):
        has_dlq = bool(topic.get("redrive_policy"))

        results.append(
            RuleResult(
                rule_id="sns_topic_dlq_configured",
                category=CATEGORY,
                severity="medium",
                passed=has_dlq,
                message="SNS topic has a redrive policy configured"
                if has_dlq
                else "SNS topic has no redrive policy - undeliverable messages will be dropped",
                resource=topic["_name"],
            )
        )

    return results


def check_lambda_timeout(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """Lambda functions should have a timeout set above the 3-second default."""
    results = []
    default_timeout = 3

    for function in resources.get("aws_lambda_function", []):
        timeout = function.get("timeout", default_timeout)
        is_configured = timeout > default_timeout

        results.append(
            RuleResult(
                rule_id="lambda_timeout_configured",
                category=CATEGORY,
                severity="medium",
                passed=is_configured,
                message=f"Lambda function has a timeout of {timeout}s"
                if is_configured
                else f"Lambda function is using the {default_timeout}s default timeout"
                " - this is too low for most production workloads",
                resource=function["_name"],
            )
        )

    return results


def check_alb_target_group_health_check(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ALB target groups should have an explicit health check configured."""
    results = []

    for tg in resources.get("aws_lb_target_group", []):
        health_check = tg.get("health_check", {})
        # health_check may be a list due to hcl2 block parsing
        if isinstance(health_check, list):
            health_check = health_check[0] if health_check else {}
        has_health_check = bool(health_check)

        results.append(
            RuleResult(
                rule_id="alb_target_group_health_check",
                category=CATEGORY,
                severity="medium",
                passed=has_health_check,
                message="ALB target group has a health check configured"
                if has_health_check
                else "ALB target group has no explicit health check"
                " - unhealthy targets may receive traffic",
                resource=tg["_name"],
            )
        )

    return results


def check_rds_auto_minor_version_upgrade(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """RDS instances should have automatic minor version upgrades enabled."""
    results = []

    for instance in resources.get("aws_db_instance", []):
        # Default in AWS and Terraform is True - only fails if explicitly disabled
        has_upgrade = instance.get("auto_minor_version_upgrade", True)

        results.append(
            RuleResult(
                rule_id="rds_auto_minor_version_upgrade",
                category=CATEGORY,
                severity="low",
                passed=has_upgrade,
                message="RDS instance has automatic minor version upgrades enabled"
                if has_upgrade
                else "RDS instance has automatic minor version upgrades disabled"
                " - security patches will not be applied automatically",
                resource=instance["_name"],
            )
        )

    return results


def check_elasticache_multi_az(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ElastiCache replication groups should have Multi-AZ enabled for high availability."""
    results = []

    for replication_group in resources.get("aws_elasticache_replication_group", []):
        has_multi_az = replication_group.get("multi_az_enabled", False)

        results.append(
            RuleResult(
                rule_id="elasticache_multi_az",
                category=CATEGORY,
                severity="medium",
                passed=has_multi_az,
                message="ElastiCache replication group has Multi-AZ enabled"
                if has_multi_az
                else "ElastiCache replication group does not have Multi-AZ enabled"
                " - a zone failure will cause downtime",
                resource=replication_group["_name"],
            )
        )

    return results


def check_ecs_task_definition_cpu_memory(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ECS task definitions should have explicit CPU and memory limits set."""
    results = []

    for task_def in resources.get("aws_ecs_task_definition", []):
        has_cpu = bool(task_def.get("cpu"))
        has_memory = bool(task_def.get("memory"))
        is_configured = has_cpu and has_memory

        results.append(
            RuleResult(
                rule_id="ecs_task_definition_cpu_memory",
                category=CATEGORY,
                severity="medium",
                passed=is_configured,
                message="ECS task definition has CPU and memory limits set"
                if is_configured
                else "ECS task definition is missing CPU or memory limits"
                " - tasks may starve or be terminated unexpectedly",
                resource=task_def["_name"],
            )
        )

    return results
