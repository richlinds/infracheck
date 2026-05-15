from infracheck.analyzers.scoring import score_results
from infracheck.models import CategoryScore
from infracheck.rules.security import (
    check_cloudtrail_log_file_validation,
    check_ec2_imdsv2_required,
    check_ec2_no_public_ip,
    check_kms_key_rotation,
    check_lambda_no_secrets_in_env,
    check_rds_encryption,
    check_rds_iam_authentication,
    check_rds_not_publicly_accessible,
    check_s3_encryption,
    check_s3_no_public_acl,
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
        *check_s3_encryption(resources),
        *check_rds_encryption(resources),
        *check_lambda_no_secrets_in_env(resources),
        *check_kms_key_rotation(resources),
        *check_cloudtrail_log_file_validation(resources),
        *check_rds_iam_authentication(resources),
        *check_s3_no_public_acl(resources),
    ]

    return CategoryScore(
        name=CATEGORY,
        score=score_results(results),
        findings=results,
    )
