import json

from infracheck.models import RuleResult

CATEGORY = "scalability"


def check_autoscaling_configured(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """There should be at least one autoscaling group defined."""
    has_asg = len(resources.get("aws_autoscaling_group", [])) > 0
    return [
        RuleResult(
            rule_id="autoscaling_configured",
            category=CATEGORY,
            severity="medium",
            passed=has_asg,
            message="At least one autoscaling group is configured"
            if has_asg
            else "No autoscaling groups found - compute cannot scale automatically under load",
        )
    ]


def check_autoscaling_elb_health_check(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ASGs attached to a load balancer should use ELB health checks, not EC2 health checks."""
    results = []

    for asg in resources.get("aws_autoscaling_group", []):
        is_attached_to_lb = bool(asg.get("target_group_arns") or asg.get("load_balancers"))

        if is_attached_to_lb:
            uses_elb_health_check = asg.get("health_check_type", "EC2") == "ELB"
            results.append(
                RuleResult(
                    rule_id="autoscaling_elb_health_check",
                    category=CATEGORY,
                    severity="high",
                    passed=uses_elb_health_check,
                    message="Autoscaling group uses ELB health checks"
                    if uses_elb_health_check
                    else "Autoscaling group uses EC2 health checks - unhealthy instances"
                    " may stay in rotation when attached to a load balancer",
                    resource=asg["_name"],
                )
            )

    return results


def check_lambda_reserved_concurrency(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """Lambda functions should have a reserved concurrency limit set."""
    results = []

    for function in resources.get("aws_lambda_function", []):
        # -1 means no limit set; 0 disables the function entirely
        concurrency = function.get("reserved_concurrent_executions", -1)
        has_limit = concurrency > 0
        results.append(
            RuleResult(
                rule_id="lambda_reserved_concurrency",
                category=CATEGORY,
                severity="high",
                passed=has_limit,
                message="Lambda function has a reserved concurrency limit"
                if has_limit
                else "Lambda function has no reserved concurrency limit - it can exhaust"
                " the account-wide concurrency quota and throttle other functions",
                resource=function["_name"],
            )
        )

    return results


def check_elasticache_automatic_failover(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ElastiCache replication groups should have automatic failover enabled."""
    results = []

    for replication_group in resources.get("aws_elasticache_replication_group", []):
        has_failover = replication_group.get("automatic_failover_enabled", False)
        results.append(
            RuleResult(
                rule_id="elasticache_automatic_failover",
                category=CATEGORY,
                severity="medium",
                passed=has_failover,
                message="ElastiCache replication group has automatic failover enabled"
                if has_failover
                else "ElastiCache replication group does not have automatic failover enabled"
                " - the cluster will go offline if the primary node fails",
                resource=replication_group["_name"],
            )
        )

    return results


def check_elasticache_cluster_size(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ElastiCache replication groups should have at least 2 nodes for read scaling."""
    results = []
    minimum_nodes = 2

    for replication_group in resources.get("aws_elasticache_replication_group", []):
        node_count = replication_group.get("num_cache_clusters", 1)
        has_sufficient_nodes = node_count >= minimum_nodes
        results.append(
            RuleResult(
                rule_id="elasticache_cluster_size",
                category=CATEGORY,
                severity="medium",
                passed=has_sufficient_nodes,
                message=f"ElastiCache replication group has {node_count} nodes"
                if has_sufficient_nodes
                else f"ElastiCache replication group has only {node_count} node(s)"
                f" - minimum {minimum_nodes} recommended for read scaling",
                resource=replication_group["_name"],
            )
        )

    return results


def check_elasticache_backup_retention(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ElastiCache Redis clusters should retain snapshots for at least 1 day."""
    results = []
    minimum_retention_days = 1

    for replication_group in resources.get("aws_elasticache_replication_group", []):
        retention_days = replication_group.get("snapshot_retention_limit", 0)
        has_backups = retention_days >= minimum_retention_days
        results.append(
            RuleResult(
                rule_id="elasticache_backup_retention",
                category=CATEGORY,
                severity="medium",
                passed=has_backups,
                message=f"ElastiCache replication group retains snapshots for {retention_days} days"
                if has_backups
                else "ElastiCache replication group has no snapshot retention configured"
                " - data will be lost if the cluster fails",
                resource=replication_group["_name"],
            )
        )

    return results


def check_load_balancer_cross_zone(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """Load balancers should have cross-zone load balancing enabled."""
    results = []

    for load_balancer in resources.get("aws_lb", []):
        # ALBs have cross-zone enabled by default; NLBs and GWLBs do not
        lb_type = load_balancer.get("load_balancer_type", "application")
        if lb_type in ("network", "gateway"):
            has_cross_zone = load_balancer.get("enable_cross_zone_load_balancing", False)
            results.append(
                RuleResult(
                    rule_id="load_balancer_cross_zone",
                    category=CATEGORY,
                    severity="medium",
                    passed=has_cross_zone,
                    message="Load balancer has cross-zone load balancing enabled"
                    if has_cross_zone
                    else "Load balancer does not have cross-zone load balancing enabled"
                    " - traffic will be unevenly distributed across availability zones",
                    resource=load_balancer["_name"],
                )
            )

    return results


def check_rds_read_replicas(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """RDS instances under read-heavy workloads should have read replicas."""
    results = []

    for instance in resources.get("aws_db_instance", []):
        # A read replica is defined by setting replicate_source_db on a separate instance
        is_replica = "replicate_source_db" in instance
        has_replica = any(
            "replicate_source_db" in other
            for other in resources.get("aws_db_instance", [])
            if other["_name"] != instance["_name"]
        )

        # Only flag primary instances (not the replicas themselves)
        if not is_replica:
            results.append(
                RuleResult(
                    rule_id="rds_read_replicas",
                    category=CATEGORY,
                    severity="low",
                    passed=has_replica,
                    message="RDS instance has a read replica configured"
                    if has_replica
                    else "RDS instance has no read replicas - consider adding one"
                    " for read-heavy workloads",
                    resource=instance["_name"],
                )
            )

    return results


def check_ecs_service_autoscaling(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ECS services should have Application Auto Scaling configured."""
    results = []

    has_ecs_autoscaling = any(
        target.get("service_namespace") == "ecs"
        for target in resources.get("aws_appautoscaling_target", [])
    )

    for service in resources.get("aws_ecs_service", []):
        results.append(
            RuleResult(
                rule_id="ecs_service_autoscaling",
                category=CATEGORY,
                severity="medium",
                passed=has_ecs_autoscaling,
                message="ECS service has autoscaling configured"
                if has_ecs_autoscaling
                else "ECS service has no autoscaling configured - it cannot scale with demand",
                resource=service["_name"],
            )
        )

    return results


def check_lambda_memory_size(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """Lambda functions should use more than the 128 MB default memory allocation."""
    results = []
    default_memory = 128

    for function in resources.get("aws_lambda_function", []):
        memory = function.get("memory_size", default_memory)
        above_default = memory > default_memory

        results.append(
            RuleResult(
                rule_id="lambda_memory_size",
                category=CATEGORY,
                severity="low",
                passed=above_default,
                message=f"Lambda function has {memory} MB of memory allocated"
                if above_default
                else f"Lambda function is using the default {default_memory} MB memory"
                " - this is often a performance bottleneck",
                resource=function["_name"],
            )
        )

    return results


def check_rds_not_micro_instance(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """RDS instances should not use micro instance classes in production."""
    results = []
    micro_classes = {"db.t2.micro", "db.t3.micro", "db.t4g.micro"}

    for instance in resources.get("aws_db_instance", []):
        instance_class = instance.get("instance_class", "")
        is_micro = instance_class in micro_classes

        results.append(
            RuleResult(
                rule_id="rds_not_micro_instance",
                category=CATEGORY,
                severity="medium",
                passed=not is_micro,
                message=f"RDS instance class is {instance_class}"
                if not is_micro
                else f"RDS instance is using {instance_class}"
                " - micro instances are not suitable for production workloads",
                resource=instance["_name"],
            )
        )

    return results


def check_ecs_service_multiple_tasks(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """ECS services should run at least 2 tasks for availability and load distribution."""
    results = []

    for service in resources.get("aws_ecs_service", []):
        desired_count = service.get("desired_count", 1)
        has_multiple = desired_count >= 2

        results.append(
            RuleResult(
                rule_id="ecs_service_multiple_tasks",
                category=CATEGORY,
                severity="medium",
                passed=has_multiple,
                message=f"ECS service has {desired_count} tasks configured"
                if has_multiple
                else f"ECS service has only {desired_count} task configured"
                " - a single task cannot handle load distribution or survive restarts",
                resource=service["_name"],
            )
        )

    return results


def check_sqs_max_receive_count(resources: dict[str, list[dict]]) -> list[RuleResult]:
    """SQS queues with a DLQ should set maxReceiveCount to at least 3."""
    results = []
    minimum_receive_count = 3

    for queue in resources.get("aws_sqs_queue", []):
        redrive_policy = queue.get("redrive_policy")
        if not redrive_policy:
            continue  # No DLQ configured; covered by sqs_dlq_configured

        try:
            policy = (
                json.loads(redrive_policy) if isinstance(redrive_policy, str) else redrive_policy
            )
            max_receive_count = int(policy.get("maxReceiveCount", 0))
        except (json.JSONDecodeError, ValueError, TypeError):
            continue

        is_sufficient = max_receive_count >= minimum_receive_count
        results.append(
            RuleResult(
                rule_id="sqs_max_receive_count",
                category=CATEGORY,
                severity="medium",
                passed=is_sufficient,
                message=f"SQS queue maxReceiveCount is {max_receive_count}"
                if is_sufficient
                else f"SQS queue maxReceiveCount is {max_receive_count}"
                f" - minimum {minimum_receive_count} recommended to avoid premature DLQ routing",
                resource=queue["_name"],
            )
        )

    return results
