from infracheck.analyzers.scoring import score_results
from infracheck.models import CategoryScore
from infracheck.rules.security import (
    check_ec2_imdsv2_required,
    check_ec2_no_public_ip,
    check_rds_not_publicly_accessible,
    check_s3_public_access,
    check_security_group_open_ingress,
)

CATEGORY = "security"


def run(resources: dict[str, list[dict]]) -> CategoryScore:
    """Run all security rules against the parsed resources."""
    results = [
        *check_s3_public_access(resources),
        *check_rds_not_publicly_accessible(resources),
        *check_security_group_open_ingress(resources),
        *check_ec2_imdsv2_required(resources),
        *check_ec2_no_public_ip(resources),
    ]

    return CategoryScore(
        name=CATEGORY,
        score=score_results(results),
        findings=results,
    )
