from infracheck.models import RuleResult

CATEGORY = "observability"


def check_cloudwatch_alarms_exist(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """There should be at least one CloudWatch alarm defined."""
    has_alarms = len(resources.get("aws_cloudwatch_metric_alarm", [])) > 0
    return [
        RuleResult(
            rule_id="cloudwatch_alarms_exist",
            category=CATEGORY,
            severity="medium",
            passed=has_alarms,
            message="At least one CloudWatch alarm is configured"
            if has_alarms
            else "No CloudWatch alarms found - issues may go undetected in production",
        )
    ]


def check_lambda_log_groups(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """Each Lambda function should have a corresponding CloudWatch log group."""
    results = []

    log_group_names = {
        log_group.get("name", "") for log_group in resources.get("aws_cloudwatch_log_group", [])
    }

    for function in resources.get("aws_lambda_function", []):
        function_name = function.get("function_name", function["_name"])
        expected_log_group = f"/aws/lambda/{function_name}"
        has_log_group = expected_log_group in log_group_names

        results.append(
            RuleResult(
                rule_id="lambda_log_group_exists",
                category=CATEGORY,
                severity="medium",
                passed=has_log_group,
                message=f"Lambda function has a log group at {expected_log_group}"
                if has_log_group
                else "Lambda function is missing a log group - logs may not be retained",
                resource=function["_name"],
            )
        )

    return results


def check_lambda_xray_tracing(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """Lambda functions should have X-Ray tracing enabled for distributed tracing."""
    results = []

    for function in resources.get("aws_lambda_function", []):
        tracing_config = function.get("tracing_config", {})
        # tracing_config may be a list due to hcl2 block parsing
        if isinstance(tracing_config, list):
            tracing_config = tracing_config[0] if tracing_config else {}
        has_tracing = tracing_config.get("mode") == "Active"

        results.append(
            RuleResult(
                rule_id="lambda_xray_tracing",
                category=CATEGORY,
                severity="medium",
                passed=has_tracing,
                message="Lambda function has X-Ray tracing enabled"
                if has_tracing
                else "Lambda function does not have X-Ray tracing enabled"
                " - distributed tracing will not be available",
                resource=function["_name"],
            )
        )

    return results


def check_log_group_retention(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """CloudWatch log groups should have a retention period set to avoid unbounded cost."""
    results = []

    for log_group in resources.get("aws_cloudwatch_log_group", []):
        retention_days = log_group.get("retention_in_days", 0)
        has_retention = retention_days > 0

        results.append(
            RuleResult(
                rule_id="log_group_retention_set",
                category=CATEGORY,
                severity="medium",
                passed=has_retention,
                message=f"CloudWatch log group has a retention period of {retention_days} days"
                if has_retention
                else "CloudWatch log group has no retention period - logs will be kept forever"
                " and costs will grow unbounded",
                resource=log_group["_name"],
            )
        )

    return results


def check_alb_access_logging(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ALBs should have access logging enabled to capture all request-level data."""
    results = []

    for load_balancer in resources.get("aws_lb", []):
        lb_type = load_balancer.get("load_balancer_type", "application")
        if lb_type != "application":
            continue

        access_logs = load_balancer.get("access_logs", {})
        # access_logs may be a list due to hcl2 block parsing
        if isinstance(access_logs, list):
            access_logs = access_logs[0] if access_logs else {}
        has_logging = access_logs.get("enabled", False)

        results.append(
            RuleResult(
                rule_id="alb_access_logging_enabled",
                category=CATEGORY,
                severity="medium",
                passed=has_logging,
                message="ALB has access logging enabled"
                if has_logging
                else "ALB does not have access logging enabled - request-level data will be lost",
                resource=load_balancer["_name"],
            )
        )

    return results


def check_cloudtrail_cloudwatch_integration(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """CloudTrail trails should be integrated with CloudWatch Logs for real-time monitoring."""
    results = []

    for trail in resources.get("aws_cloudtrail", []):
        has_integration = bool(trail.get("cloud_watch_logs_group_arn"))

        results.append(
            RuleResult(
                rule_id="cloudtrail_cloudwatch_integration",
                category=CATEGORY,
                severity="high",
                passed=has_integration,
                message="CloudTrail trail is integrated with CloudWatch Logs"
                if has_integration
                else "CloudTrail trail is not integrated with CloudWatch Logs"
                " - API activity will not feed into alarms or metric filters",
                resource=trail["_name"],
            )
        )

    return results


def check_vpc_flow_logs(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """Each VPC should have flow logs enabled for network-level visibility."""
    results = []

    vpc_ids_with_flow_logs = {
        flow_log.get("vpc_id")
        for flow_log in resources.get("aws_flow_log", [])
        if flow_log.get("vpc_id")
    }

    for vpc in resources.get("aws_vpc", []):
        has_flow_logs = vpc["_name"] in vpc_ids_with_flow_logs

        results.append(
            RuleResult(
                rule_id="vpc_flow_logs_enabled",
                category=CATEGORY,
                severity="high",
                passed=has_flow_logs,
                message="VPC has flow logs enabled"
                if has_flow_logs
                else "VPC does not have flow logs enabled - network traffic will not be logged",
                resource=vpc["_name"],
            )
        )

    return results


def check_ecs_container_insights(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ECS clusters should have Container Insights enabled for enhanced monitoring."""
    results = []

    for cluster in resources.get("aws_ecs_cluster", []):
        settings = cluster.get("setting", [])
        # setting may be a single dict due to hcl2 block parsing
        if isinstance(settings, dict):
            settings = [settings]

        has_insights = any(
            setting.get("name") == "containerInsights" and setting.get("value") == "enabled"
            for setting in settings
        )

        results.append(
            RuleResult(
                rule_id="ecs_container_insights_enabled",
                category=CATEGORY,
                severity="medium",
                passed=has_insights,
                message="ECS cluster has Container Insights enabled"
                if has_insights
                else "ECS cluster does not have Container Insights enabled"
                " - container-level metrics and logs will not be available",
                resource=cluster["_name"],
            )
        )

    return results


def check_rds_enhanced_monitoring(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """RDS instances should have enhanced monitoring enabled for OS-level metrics."""
    results = []

    for instance in resources.get("aws_db_instance", []):
        monitoring_interval = instance.get("monitoring_interval", 0)
        has_monitoring = monitoring_interval > 0
        msg = f"RDS instance has enhanced monitoring enabled (interval: {monitoring_interval}s)"

        results.append(
            RuleResult(
                rule_id="rds_enhanced_monitoring",
                category=CATEGORY,
                severity="low",
                passed=has_monitoring,
                message=msg
                if has_monitoring
                else "RDS instance does not have enhanced monitoring enabled"
                " - OS-level metrics will not be visible",
                resource=instance["_name"],
            )
        )

    return results


def check_s3_server_access_logging(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """S3 buckets should have server access logging enabled to record access requests."""
    results = []

    for logging_config in resources.get("aws_s3_bucket_logging", []):
        has_logging = bool(logging_config.get("target_bucket"))

        results.append(
            RuleResult(
                rule_id="s3_server_access_logging_enabled",
                category=CATEGORY,
                severity="low",
                passed=has_logging,
                message="S3 bucket has server access logging enabled"
                if has_logging
                else "S3 bucket does not have server access logging enabled"
                " - access requests will not be recorded",
                resource=logging_config["_name"],
            )
        )

    return results


def check_rds_performance_insights(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """RDS instances should have Performance Insights enabled for query-level monitoring."""
    results = []

    for instance in resources.get("aws_db_instance", []):
        has_insights = instance.get("performance_insights_enabled", False)

        results.append(
            RuleResult(
                rule_id="rds_performance_insights",
                category=CATEGORY,
                severity="low",
                passed=has_insights,
                message="RDS instance has Performance Insights enabled"
                if has_insights
                else "RDS instance does not have Performance Insights enabled"
                " - query-level performance data will not be available",
                resource=instance["_name"],
            )
        )

    return results


def check_elasticache_log_delivery(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ElastiCache replication groups should have log delivery configured."""
    results = []

    for replication_group in resources.get("aws_elasticache_replication_group", []):
        log_delivery = replication_group.get("log_delivery_configuration", [])
        # log_delivery_configuration may be a single dict due to hcl2 block parsing
        if isinstance(log_delivery, dict):
            log_delivery = [log_delivery]
        has_logging = len(log_delivery) > 0

        results.append(
            RuleResult(
                rule_id="elasticache_log_delivery",
                category=CATEGORY,
                severity="low",
                passed=has_logging,
                message="ElastiCache replication group has log delivery configured"
                if has_logging
                else "ElastiCache replication group has no log delivery configured"
                " - slow logs and engine logs will not be captured",
                resource=replication_group["_name"],
            )
        )

    return results


def check_s3_request_metrics(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """S3 buckets should have request metrics enabled for visibility into access patterns."""
    results = []

    has_metrics = len(resources.get("aws_s3_bucket_metric", [])) > 0

    for bucket in resources.get("aws_s3_bucket", []):
        results.append(
            RuleResult(
                rule_id="s3_request_metrics_enabled",
                category=CATEGORY,
                severity="low",
                passed=has_metrics,
                message="S3 bucket has request metrics enabled"
                if has_metrics
                else "S3 bucket has no request metrics configured"
                " - access patterns will not be visible in CloudWatch",
                resource=bucket["_name"],
            )
        )

    return results


def check_cloudwatch_dashboard_exists(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """There should be at least one CloudWatch dashboard for operational visibility."""
    has_dashboard = len(resources.get("aws_cloudwatch_dashboard", [])) > 0
    return [
        RuleResult(
            rule_id="cloudwatch_dashboard_exists",
            category=CATEGORY,
            severity="low",
            passed=has_dashboard,
            message="At least one CloudWatch dashboard is configured"
            if has_dashboard
            else "No CloudWatch dashboards found - there is no central view of system health",
        )
    ]
