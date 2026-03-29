from infracheck.analyzers.scoring import score_results
from infracheck.models import CategoryScore
from infracheck.rules.scalability import (
    check_autoscaling_configured,
    check_autoscaling_elb_health_check,
    check_elasticache_automatic_failover,
    check_elasticache_backup_retention,
    check_elasticache_cluster_size,
    check_lambda_reserved_concurrency,
    check_load_balancer_cross_zone,
    check_rds_read_replicas,
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
    ]

    return CategoryScore(
        name=CATEGORY,
        score=score_results(results),
        findings=results,
    )
