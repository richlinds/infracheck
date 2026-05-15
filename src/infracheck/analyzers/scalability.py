from infracheck.analyzers.scoring import score_results
from infracheck.models import CategoryScore
from infracheck.rules.scalability import (
    check_autoscaling_configured,
    check_autoscaling_elb_health_check,
    check_ecs_service_autoscaling,
    check_ecs_service_multiple_tasks,
    check_elasticache_automatic_failover,
    check_elasticache_backup_retention,
    check_elasticache_cluster_size,
    check_lambda_memory_size,
    check_lambda_reserved_concurrency,
    check_load_balancer_cross_zone,
    check_rds_not_micro_instance,
    check_rds_read_replicas,
    check_sqs_max_receive_count,
)

CATEGORY = "scalability"


def run(resources: dict[str, list[dict]]) -> CategoryScore:
    """Run all scalability rules against the parsed resources."""
    results = [
        *check_autoscaling_configured(resources),
        *check_autoscaling_elb_health_check(resources),
        *check_lambda_reserved_concurrency(resources),
        *check_rds_read_replicas(resources),
        *check_elasticache_automatic_failover(resources),
        *check_elasticache_backup_retention(resources),
        *check_elasticache_cluster_size(resources),
        *check_load_balancer_cross_zone(resources),
        *check_ecs_service_autoscaling(resources),
        *check_sqs_max_receive_count(resources),
        *check_lambda_memory_size(resources),
        *check_rds_not_micro_instance(resources),
        *check_ecs_service_multiple_tasks(resources),
    ]

    return CategoryScore(
        name=CATEGORY,
        score=score_results(results),
        findings=results,
    )
