"""Unit tests for all rule functions."""

import json

from infracheck.rules.fault_tolerance import (
    check_alb_target_group_health_check,
    check_ecs_min_healthy_percent,
    check_ecs_task_definition_cpu_memory,
    check_elasticache_multi_az,
    check_lambda_timeout,
    check_rds_auto_minor_version_upgrade,
    check_s3_versioning,
    check_sns_topic_dlq,
)
from infracheck.rules.observability import (
    check_cloudwatch_dashboard_exists,
    check_ecs_container_insights,
    check_elasticache_log_delivery,
    check_rds_enhanced_monitoring,
    check_rds_performance_insights,
    check_s3_request_metrics,
    check_s3_server_access_logging,
)
from infracheck.rules.scalability import (
    check_ecs_service_autoscaling,
    check_ecs_service_multiple_tasks,
    check_lambda_memory_size,
    check_rds_not_micro_instance,
    check_sqs_max_receive_count,
)
from infracheck.rules.security import (
    check_cloudtrail_log_file_validation,
    check_kms_key_rotation,
    check_lambda_no_secrets_in_env,
    check_rds_encryption,
    check_rds_iam_authentication,
    check_s3_encryption,
    check_s3_no_public_acl,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resources(**kwargs):
    """Build a resources dict; each value is a list of resource dicts."""
    return {key: value for key, value in kwargs.items()}


def _named(name: str, **attrs) -> dict:
    """Build a resource dict with _name set."""
    return {"_name": name, **attrs}


# ---------------------------------------------------------------------------
# Fault Tolerance — check_s3_versioning
# ---------------------------------------------------------------------------


class TestS3Versioning:
    def test_passes_when_versioning_enabled(self):
        resources = _resources(
            aws_s3_bucket_versioning=[
                _named(
                    "my_bucket_versioning",
                    versioning_configuration={"status": "Enabled"},
                )
            ]
        )
        results = check_s3_versioning(resources)
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].rule_id == "s3_versioning_enabled"
        assert results[0].resource == "my_bucket_versioning"

    def test_fails_when_versioning_suspended(self):
        resources = _resources(
            aws_s3_bucket_versioning=[
                _named(
                    "my_bucket_versioning",
                    versioning_configuration={"status": "Suspended"},
                )
            ]
        )
        results = check_s3_versioning(resources)
        assert results[0].passed is False

    def test_fails_when_versioning_configuration_missing(self):
        resources = _resources(aws_s3_bucket_versioning=[_named("my_bucket_versioning")])
        results = check_s3_versioning(resources)
        assert results[0].passed is False

    def test_handles_hcl2_list_wrapped_block(self):
        resources = _resources(
            aws_s3_bucket_versioning=[
                _named(
                    "my_bucket_versioning",
                    versioning_configuration=[{"status": "Enabled"}],
                )
            ]
        )
        results = check_s3_versioning(resources)
        assert results[0].passed is True

    def test_returns_empty_when_no_versioning_resources(self):
        assert check_s3_versioning({}) == []


# ---------------------------------------------------------------------------
# Fault Tolerance — check_ecs_min_healthy_percent
# ---------------------------------------------------------------------------


class TestEcsMinHealthyPercent:
    def test_passes_when_above_minimum(self):
        resources = _resources(
            aws_ecs_service=[_named("my_service", deployment_minimum_healthy_percent=100)]
        )
        results = check_ecs_min_healthy_percent(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "ecs_min_healthy_percent"

    def test_passes_exactly_at_minimum(self):
        resources = _resources(
            aws_ecs_service=[_named("my_service", deployment_minimum_healthy_percent=50)]
        )
        results = check_ecs_min_healthy_percent(resources)
        assert results[0].passed is True

    def test_fails_below_minimum(self):
        resources = _resources(
            aws_ecs_service=[_named("my_service", deployment_minimum_healthy_percent=0)]
        )
        results = check_ecs_min_healthy_percent(resources)
        assert results[0].passed is False

    def test_defaults_to_passing_when_attribute_missing(self):
        # Default of 100 is sufficient
        resources = _resources(aws_ecs_service=[_named("my_service")])
        results = check_ecs_min_healthy_percent(resources)
        assert results[0].passed is True

    def test_returns_empty_when_no_ecs_services(self):
        assert check_ecs_min_healthy_percent({}) == []


# ---------------------------------------------------------------------------
# Fault Tolerance — check_sns_topic_dlq
# ---------------------------------------------------------------------------


class TestSnsTopicDlq:
    def test_passes_when_redrive_policy_set(self):
        resources = _resources(
            aws_sns_topic=[
                _named("my_topic", redrive_policy='{"deadLetterTargetArn": "arn:aws:sqs:..."}')
            ]
        )
        results = check_sns_topic_dlq(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "sns_topic_dlq_configured"

    def test_fails_when_no_redrive_policy(self):
        resources = _resources(aws_sns_topic=[_named("my_topic")])
        results = check_sns_topic_dlq(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_sns_topics(self):
        assert check_sns_topic_dlq({}) == []


# ---------------------------------------------------------------------------
# Security — check_s3_encryption
# ---------------------------------------------------------------------------


class TestS3Encryption:
    def test_passes_when_rule_block_present(self):
        resources = _resources(
            aws_s3_bucket_server_side_encryption_configuration=[
                _named(
                    "my_bucket_sse",
                    rule=[{"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}],
                )
            ]
        )
        results = check_s3_encryption(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "s3_encryption_enabled"

    def test_fails_when_rule_block_absent(self):
        resources = _resources(
            aws_s3_bucket_server_side_encryption_configuration=[_named("my_bucket_sse")]
        )
        results = check_s3_encryption(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_sse_resources(self):
        assert check_s3_encryption({}) == []


# ---------------------------------------------------------------------------
# Security — check_rds_encryption
# ---------------------------------------------------------------------------


class TestRdsEncryption:
    def test_passes_when_storage_encrypted_true(self):
        resources = _resources(aws_db_instance=[_named("my_db", storage_encrypted=True)])
        results = check_rds_encryption(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "rds_storage_encrypted"

    def test_fails_when_storage_encrypted_false(self):
        resources = _resources(aws_db_instance=[_named("my_db", storage_encrypted=False)])
        results = check_rds_encryption(resources)
        assert results[0].passed is False

    def test_fails_when_attribute_missing(self):
        resources = _resources(aws_db_instance=[_named("my_db")])
        results = check_rds_encryption(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_rds_instances(self):
        assert check_rds_encryption({}) == []


# ---------------------------------------------------------------------------
# Security — check_lambda_no_secrets_in_env
# ---------------------------------------------------------------------------


class TestLambdaNoSecretsInEnv:
    def test_passes_when_no_suspicious_keys(self):
        resources = _resources(
            aws_lambda_function=[
                _named(
                    "my_fn",
                    environment={"variables": {"LOG_LEVEL": "INFO", "REGION": "us-east-1"}},
                )
            ]
        )
        results = check_lambda_no_secrets_in_env(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "lambda_no_secrets_in_env"

    def test_fails_when_api_key_present(self):
        resources = _resources(
            aws_lambda_function=[
                _named("my_fn", environment={"variables": {"THIRD_PARTY_API_KEY": "abc123"}})
            ]
        )
        results = check_lambda_no_secrets_in_env(resources)
        assert results[0].passed is False

    def test_fails_when_password_present(self):
        resources = _resources(
            aws_lambda_function=[
                _named("my_fn", environment={"variables": {"DB_PASSWORD": "hunter2"}})
            ]
        )
        results = check_lambda_no_secrets_in_env(resources)
        assert results[0].passed is False

    def test_fails_when_secret_key_present(self):
        resources = _resources(
            aws_lambda_function=[
                _named("my_fn", environment={"variables": {"SECRET_KEY": "s3cr3t"}})
            ]
        )
        results = check_lambda_no_secrets_in_env(resources)
        assert results[0].passed is False

    def test_passes_when_no_environment_block(self):
        resources = _resources(aws_lambda_function=[_named("my_fn")])
        results = check_lambda_no_secrets_in_env(resources)
        assert results[0].passed is True

    def test_handles_hcl2_list_wrapped_environment(self):
        resources = _resources(
            aws_lambda_function=[
                _named(
                    "my_fn",
                    environment=[{"variables": {"DB_PASSWORD": "hunter2"}}],
                )
            ]
        )
        results = check_lambda_no_secrets_in_env(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_lambda_functions(self):
        assert check_lambda_no_secrets_in_env({}) == []


# ---------------------------------------------------------------------------
# Scalability — check_ecs_service_autoscaling
# ---------------------------------------------------------------------------


class TestEcsServiceAutoscaling:
    def test_passes_when_ecs_autoscaling_target_exists(self):
        resources = _resources(
            aws_ecs_service=[_named("my_service")],
            aws_appautoscaling_target=[
                _named(
                    "ecs_target",
                    service_namespace="ecs",
                    scalable_dimension="ecs:service:DesiredCount",
                )
            ],
        )
        results = check_ecs_service_autoscaling(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "ecs_service_autoscaling"

    def test_fails_when_no_ecs_autoscaling_target(self):
        resources = _resources(aws_ecs_service=[_named("my_service")])
        results = check_ecs_service_autoscaling(resources)
        assert results[0].passed is False

    def test_fails_when_autoscaling_target_is_not_ecs_namespace(self):
        resources = _resources(
            aws_ecs_service=[_named("my_service")],
            aws_appautoscaling_target=[_named("rds_target", service_namespace="rds")],
        )
        results = check_ecs_service_autoscaling(resources)
        assert results[0].passed is False

    def test_produces_one_result_per_ecs_service(self):
        resources = _resources(
            aws_ecs_service=[_named("svc_a"), _named("svc_b")],
        )
        results = check_ecs_service_autoscaling(resources)
        assert len(results) == 2

    def test_returns_empty_when_no_ecs_services(self):
        assert check_ecs_service_autoscaling({}) == []


# ---------------------------------------------------------------------------
# Scalability — check_sqs_max_receive_count
# ---------------------------------------------------------------------------


class TestSqsMaxReceiveCount:
    def test_passes_when_max_receive_count_sufficient(self):
        policy = json.dumps({"deadLetterTargetArn": "arn:...", "maxReceiveCount": 5})
        resources = _resources(aws_sqs_queue=[_named("my_queue", redrive_policy=policy)])
        results = check_sqs_max_receive_count(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "sqs_max_receive_count"

    def test_passes_exactly_at_minimum(self):
        policy = json.dumps({"deadLetterTargetArn": "arn:...", "maxReceiveCount": 3})
        resources = _resources(aws_sqs_queue=[_named("my_queue", redrive_policy=policy)])
        results = check_sqs_max_receive_count(resources)
        assert results[0].passed is True

    def test_fails_below_minimum(self):
        policy = json.dumps({"deadLetterTargetArn": "arn:...", "maxReceiveCount": 1})
        resources = _resources(aws_sqs_queue=[_named("my_queue", redrive_policy=policy)])
        results = check_sqs_max_receive_count(resources)
        assert results[0].passed is False

    def test_skips_queues_without_dlq(self):
        resources = _resources(aws_sqs_queue=[_named("my_queue")])
        results = check_sqs_max_receive_count(resources)
        assert results == []

    def test_skips_unparseable_redrive_policy(self):
        resources = _resources(
            aws_sqs_queue=[_named("my_queue", redrive_policy="${var.redrive_policy}")]
        )
        results = check_sqs_max_receive_count(resources)
        assert results == []

    def test_returns_empty_when_no_sqs_queues(self):
        assert check_sqs_max_receive_count({}) == []


# ---------------------------------------------------------------------------
# Observability — check_ecs_container_insights
# ---------------------------------------------------------------------------


class TestEcsContainerInsights:
    def test_passes_when_container_insights_enabled(self):
        resources = _resources(
            aws_ecs_cluster=[
                _named(
                    "my_cluster",
                    setting=[{"name": "containerInsights", "value": "enabled"}],
                )
            ]
        )
        results = check_ecs_container_insights(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "ecs_container_insights_enabled"

    def test_fails_when_container_insights_disabled(self):
        resources = _resources(
            aws_ecs_cluster=[
                _named(
                    "my_cluster",
                    setting=[{"name": "containerInsights", "value": "disabled"}],
                )
            ]
        )
        results = check_ecs_container_insights(resources)
        assert results[0].passed is False

    def test_fails_when_setting_block_missing(self):
        resources = _resources(aws_ecs_cluster=[_named("my_cluster")])
        results = check_ecs_container_insights(resources)
        assert results[0].passed is False

    def test_handles_dict_setting_block(self):
        resources = _resources(
            aws_ecs_cluster=[
                _named(
                    "my_cluster",
                    setting={"name": "containerInsights", "value": "enabled"},
                )
            ]
        )
        results = check_ecs_container_insights(resources)
        assert results[0].passed is True

    def test_returns_empty_when_no_ecs_clusters(self):
        assert check_ecs_container_insights({}) == []


# ---------------------------------------------------------------------------
# Observability — check_rds_enhanced_monitoring
# ---------------------------------------------------------------------------


class TestRdsEnhancedMonitoring:
    def test_passes_when_monitoring_interval_set(self):
        resources = _resources(aws_db_instance=[_named("my_db", monitoring_interval=60)])
        results = check_rds_enhanced_monitoring(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "rds_enhanced_monitoring"

    def test_fails_when_monitoring_interval_is_zero(self):
        resources = _resources(aws_db_instance=[_named("my_db", monitoring_interval=0)])
        results = check_rds_enhanced_monitoring(resources)
        assert results[0].passed is False

    def test_fails_when_attribute_missing(self):
        resources = _resources(aws_db_instance=[_named("my_db")])
        results = check_rds_enhanced_monitoring(resources)
        assert results[0].passed is False

    def test_severity_is_low(self):
        resources = _resources(aws_db_instance=[_named("my_db")])
        results = check_rds_enhanced_monitoring(resources)
        assert results[0].severity == "low"

    def test_returns_empty_when_no_rds_instances(self):
        assert check_rds_enhanced_monitoring({}) == []


# ---------------------------------------------------------------------------
# Observability — check_s3_server_access_logging
# ---------------------------------------------------------------------------


class TestS3ServerAccessLogging:
    def test_passes_when_target_bucket_set(self):
        resources = _resources(
            aws_s3_bucket_logging=[_named("my_bucket_logging", target_bucket="my-log-bucket")]
        )
        results = check_s3_server_access_logging(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "s3_server_access_logging_enabled"

    def test_fails_when_target_bucket_missing(self):
        resources = _resources(aws_s3_bucket_logging=[_named("my_bucket_logging")])
        results = check_s3_server_access_logging(resources)
        assert results[0].passed is False

    def test_severity_is_low(self):
        resources = _resources(aws_s3_bucket_logging=[_named("my_bucket_logging")])
        results = check_s3_server_access_logging(resources)
        assert results[0].severity == "low"

    def test_returns_empty_when_no_logging_resources(self):
        assert check_s3_server_access_logging({}) == []


# ---------------------------------------------------------------------------
# Fault Tolerance — check_lambda_timeout
# ---------------------------------------------------------------------------


class TestLambdaTimeout:
    def test_passes_when_timeout_above_default(self):
        resources = _resources(aws_lambda_function=[_named("my_fn", timeout=30)])
        results = check_lambda_timeout(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "lambda_timeout_configured"

    def test_fails_when_timeout_is_default(self):
        resources = _resources(aws_lambda_function=[_named("my_fn", timeout=3)])
        results = check_lambda_timeout(resources)
        assert results[0].passed is False

    def test_fails_when_timeout_not_set(self):
        resources = _resources(aws_lambda_function=[_named("my_fn")])
        results = check_lambda_timeout(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_functions(self):
        assert check_lambda_timeout({}) == []


# ---------------------------------------------------------------------------
# Fault Tolerance — check_alb_target_group_health_check
# ---------------------------------------------------------------------------


class TestAlbTargetGroupHealthCheck:
    def test_passes_when_health_check_configured(self):
        resources = _resources(
            aws_lb_target_group=[
                _named("my_tg", health_check={"path": "/health", "interval": 30})
            ]
        )
        results = check_alb_target_group_health_check(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "alb_target_group_health_check"

    def test_passes_when_health_check_is_list(self):
        resources = _resources(
            aws_lb_target_group=[
                _named("my_tg", health_check=[{"path": "/health"}])
            ]
        )
        results = check_alb_target_group_health_check(resources)
        assert results[0].passed is True

    def test_fails_when_no_health_check(self):
        resources = _resources(aws_lb_target_group=[_named("my_tg")])
        results = check_alb_target_group_health_check(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_target_groups(self):
        assert check_alb_target_group_health_check({}) == []


# ---------------------------------------------------------------------------
# Fault Tolerance — check_rds_auto_minor_version_upgrade
# ---------------------------------------------------------------------------


class TestRdsAutoMinorVersionUpgrade:
    def test_passes_when_enabled(self):
        resources = _resources(
            aws_db_instance=[_named("my_db", auto_minor_version_upgrade=True)]
        )
        results = check_rds_auto_minor_version_upgrade(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "rds_auto_minor_version_upgrade"

    def test_passes_when_attribute_missing(self):
        # Default in AWS/Terraform is True
        resources = _resources(aws_db_instance=[_named("my_db")])
        results = check_rds_auto_minor_version_upgrade(resources)
        assert results[0].passed is True

    def test_fails_when_explicitly_disabled(self):
        resources = _resources(
            aws_db_instance=[_named("my_db", auto_minor_version_upgrade=False)]
        )
        results = check_rds_auto_minor_version_upgrade(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_instances(self):
        assert check_rds_auto_minor_version_upgrade({}) == []


# ---------------------------------------------------------------------------
# Fault Tolerance — check_elasticache_multi_az
# ---------------------------------------------------------------------------


class TestElasticacheMultiAz:
    def test_passes_when_multi_az_enabled(self):
        resources = _resources(
            aws_elasticache_replication_group=[_named("my_cluster", multi_az_enabled=True)]
        )
        results = check_elasticache_multi_az(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "elasticache_multi_az"

    def test_fails_when_multi_az_disabled(self):
        resources = _resources(
            aws_elasticache_replication_group=[_named("my_cluster", multi_az_enabled=False)]
        )
        results = check_elasticache_multi_az(resources)
        assert results[0].passed is False

    def test_fails_when_attribute_missing(self):
        resources = _resources(
            aws_elasticache_replication_group=[_named("my_cluster")]
        )
        results = check_elasticache_multi_az(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_replication_groups(self):
        assert check_elasticache_multi_az({}) == []


# ---------------------------------------------------------------------------
# Fault Tolerance — check_ecs_task_definition_cpu_memory
# ---------------------------------------------------------------------------


class TestEcsTaskDefinitionCpuMemory:
    def test_passes_when_cpu_and_memory_set(self):
        resources = _resources(
            aws_ecs_task_definition=[_named("my_task", cpu="256", memory="512")]
        )
        results = check_ecs_task_definition_cpu_memory(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "ecs_task_definition_cpu_memory"

    def test_fails_when_cpu_missing(self):
        resources = _resources(
            aws_ecs_task_definition=[_named("my_task", memory="512")]
        )
        results = check_ecs_task_definition_cpu_memory(resources)
        assert results[0].passed is False

    def test_fails_when_memory_missing(self):
        resources = _resources(
            aws_ecs_task_definition=[_named("my_task", cpu="256")]
        )
        results = check_ecs_task_definition_cpu_memory(resources)
        assert results[0].passed is False

    def test_fails_when_both_missing(self):
        resources = _resources(aws_ecs_task_definition=[_named("my_task")])
        results = check_ecs_task_definition_cpu_memory(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_task_definitions(self):
        assert check_ecs_task_definition_cpu_memory({}) == []


# ---------------------------------------------------------------------------
# Security — check_kms_key_rotation
# ---------------------------------------------------------------------------


class TestKmsKeyRotation:
    def test_passes_when_rotation_enabled(self):
        resources = _resources(aws_kms_key=[_named("my_key", enable_key_rotation=True)])
        results = check_kms_key_rotation(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "kms_key_rotation_enabled"

    def test_fails_when_rotation_disabled(self):
        resources = _resources(aws_kms_key=[_named("my_key", enable_key_rotation=False)])
        results = check_kms_key_rotation(resources)
        assert results[0].passed is False

    def test_fails_when_attribute_missing(self):
        resources = _resources(aws_kms_key=[_named("my_key")])
        results = check_kms_key_rotation(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_kms_keys(self):
        assert check_kms_key_rotation({}) == []


# ---------------------------------------------------------------------------
# Security — check_cloudtrail_log_file_validation
# ---------------------------------------------------------------------------


class TestCloudtrailLogFileValidation:
    def test_passes_when_validation_enabled(self):
        resources = _resources(
            aws_cloudtrail=[_named("my_trail", enable_log_file_validation=True)]
        )
        results = check_cloudtrail_log_file_validation(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "cloudtrail_log_file_validation"

    def test_fails_when_validation_disabled(self):
        resources = _resources(
            aws_cloudtrail=[_named("my_trail", enable_log_file_validation=False)]
        )
        results = check_cloudtrail_log_file_validation(resources)
        assert results[0].passed is False

    def test_fails_when_attribute_missing(self):
        resources = _resources(aws_cloudtrail=[_named("my_trail")])
        results = check_cloudtrail_log_file_validation(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_trails(self):
        assert check_cloudtrail_log_file_validation({}) == []


# ---------------------------------------------------------------------------
# Security — check_rds_iam_authentication
# ---------------------------------------------------------------------------


class TestRdsIamAuthentication:
    def test_passes_when_iam_auth_enabled(self):
        resources = _resources(
            aws_db_instance=[_named("my_db", iam_database_authentication_enabled=True)]
        )
        results = check_rds_iam_authentication(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "rds_iam_authentication"

    def test_fails_when_iam_auth_disabled(self):
        resources = _resources(
            aws_db_instance=[_named("my_db", iam_database_authentication_enabled=False)]
        )
        results = check_rds_iam_authentication(resources)
        assert results[0].passed is False

    def test_fails_when_attribute_missing(self):
        resources = _resources(aws_db_instance=[_named("my_db")])
        results = check_rds_iam_authentication(resources)
        assert results[0].passed is False

    def test_severity_is_low(self):
        resources = _resources(aws_db_instance=[_named("my_db")])
        results = check_rds_iam_authentication(resources)
        assert results[0].severity == "low"

    def test_returns_empty_when_no_instances(self):
        assert check_rds_iam_authentication({}) == []


# ---------------------------------------------------------------------------
# Security — check_s3_no_public_acl
# ---------------------------------------------------------------------------


class TestS3NoPublicAcl:
    def test_passes_when_acl_is_private(self):
        resources = _resources(aws_s3_bucket_acl=[_named("my_bucket_acl", acl="private")])
        results = check_s3_no_public_acl(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "s3_bucket_acl_not_public"

    def test_passes_when_acl_not_set(self):
        resources = _resources(aws_s3_bucket_acl=[_named("my_bucket_acl")])
        results = check_s3_no_public_acl(resources)
        assert results[0].passed is True

    def test_fails_when_acl_is_public_read(self):
        resources = _resources(aws_s3_bucket_acl=[_named("my_bucket_acl", acl="public-read")])
        results = check_s3_no_public_acl(resources)
        assert results[0].passed is False

    def test_fails_when_acl_is_public_read_write(self):
        resources = _resources(
            aws_s3_bucket_acl=[_named("my_bucket_acl", acl="public-read-write")]
        )
        results = check_s3_no_public_acl(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_bucket_acls(self):
        assert check_s3_no_public_acl({}) == []


# ---------------------------------------------------------------------------
# Scalability — check_lambda_memory_size
# ---------------------------------------------------------------------------


class TestLambdaMemorySize:
    def test_passes_when_memory_above_default(self):
        resources = _resources(aws_lambda_function=[_named("my_fn", memory_size=512)])
        results = check_lambda_memory_size(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "lambda_memory_size"

    def test_fails_when_memory_is_default(self):
        resources = _resources(aws_lambda_function=[_named("my_fn", memory_size=128)])
        results = check_lambda_memory_size(resources)
        assert results[0].passed is False

    def test_fails_when_memory_not_set(self):
        resources = _resources(aws_lambda_function=[_named("my_fn")])
        results = check_lambda_memory_size(resources)
        assert results[0].passed is False

    def test_severity_is_low(self):
        resources = _resources(aws_lambda_function=[_named("my_fn")])
        results = check_lambda_memory_size(resources)
        assert results[0].severity == "low"

    def test_returns_empty_when_no_functions(self):
        assert check_lambda_memory_size({}) == []


# ---------------------------------------------------------------------------
# Scalability — check_rds_not_micro_instance
# ---------------------------------------------------------------------------


class TestRdsNotMicroInstance:
    def test_passes_when_instance_is_not_micro(self):
        resources = _resources(
            aws_db_instance=[_named("my_db", instance_class="db.t3.medium")]
        )
        results = check_rds_not_micro_instance(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "rds_not_micro_instance"

    def test_fails_when_instance_is_t3_micro(self):
        resources = _resources(
            aws_db_instance=[_named("my_db", instance_class="db.t3.micro")]
        )
        results = check_rds_not_micro_instance(resources)
        assert results[0].passed is False

    def test_fails_when_instance_is_t2_micro(self):
        resources = _resources(
            aws_db_instance=[_named("my_db", instance_class="db.t2.micro")]
        )
        results = check_rds_not_micro_instance(resources)
        assert results[0].passed is False

    def test_fails_when_instance_is_t4g_micro(self):
        resources = _resources(
            aws_db_instance=[_named("my_db", instance_class="db.t4g.micro")]
        )
        results = check_rds_not_micro_instance(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_instances(self):
        assert check_rds_not_micro_instance({}) == []


# ---------------------------------------------------------------------------
# Scalability — check_ecs_service_multiple_tasks
# ---------------------------------------------------------------------------


class TestEcsServiceMultipleTasks:
    def test_passes_when_desired_count_is_two(self):
        resources = _resources(aws_ecs_service=[_named("my_service", desired_count=2)])
        results = check_ecs_service_multiple_tasks(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "ecs_service_multiple_tasks"

    def test_passes_when_desired_count_above_two(self):
        resources = _resources(aws_ecs_service=[_named("my_service", desired_count=5)])
        results = check_ecs_service_multiple_tasks(resources)
        assert results[0].passed is True

    def test_fails_when_desired_count_is_one(self):
        resources = _resources(aws_ecs_service=[_named("my_service", desired_count=1)])
        results = check_ecs_service_multiple_tasks(resources)
        assert results[0].passed is False

    def test_fails_when_desired_count_not_set(self):
        resources = _resources(aws_ecs_service=[_named("my_service")])
        results = check_ecs_service_multiple_tasks(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_services(self):
        assert check_ecs_service_multiple_tasks({}) == []


# ---------------------------------------------------------------------------
# Observability — check_rds_performance_insights
# ---------------------------------------------------------------------------


class TestRdsPerformanceInsights:
    def test_passes_when_performance_insights_enabled(self):
        resources = _resources(
            aws_db_instance=[_named("my_db", performance_insights_enabled=True)]
        )
        results = check_rds_performance_insights(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "rds_performance_insights"

    def test_fails_when_performance_insights_disabled(self):
        resources = _resources(
            aws_db_instance=[_named("my_db", performance_insights_enabled=False)]
        )
        results = check_rds_performance_insights(resources)
        assert results[0].passed is False

    def test_fails_when_attribute_missing(self):
        resources = _resources(aws_db_instance=[_named("my_db")])
        results = check_rds_performance_insights(resources)
        assert results[0].passed is False

    def test_severity_is_low(self):
        resources = _resources(aws_db_instance=[_named("my_db")])
        results = check_rds_performance_insights(resources)
        assert results[0].severity == "low"

    def test_returns_empty_when_no_instances(self):
        assert check_rds_performance_insights({}) == []


# ---------------------------------------------------------------------------
# Observability — check_elasticache_log_delivery
# ---------------------------------------------------------------------------


class TestElasticacheLogDelivery:
    def test_passes_when_log_delivery_configured(self):
        log_config = [{"destination": "my-log-group", "log_type": "slow-log"}]
        resources = _resources(
            aws_elasticache_replication_group=[
                _named("my_cluster", log_delivery_configuration=log_config)
            ]
        )
        results = check_elasticache_log_delivery(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "elasticache_log_delivery"

    def test_passes_when_log_delivery_is_dict(self):
        log_config = {"destination": "my-log-group", "log_type": "slow-log"}
        resources = _resources(
            aws_elasticache_replication_group=[
                _named("my_cluster", log_delivery_configuration=log_config)
            ]
        )
        results = check_elasticache_log_delivery(resources)
        assert results[0].passed is True

    def test_fails_when_no_log_delivery(self):
        resources = _resources(
            aws_elasticache_replication_group=[_named("my_cluster")]
        )
        results = check_elasticache_log_delivery(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_replication_groups(self):
        assert check_elasticache_log_delivery({}) == []


# ---------------------------------------------------------------------------
# Observability — check_s3_request_metrics
# ---------------------------------------------------------------------------


class TestS3RequestMetrics:
    def test_passes_when_bucket_metric_exists(self):
        resources = _resources(
            aws_s3_bucket=[_named("my_bucket")],
            aws_s3_bucket_metric=[_named("my_metric", bucket="my_bucket")],
        )
        results = check_s3_request_metrics(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "s3_request_metrics_enabled"

    def test_fails_when_no_bucket_metrics(self):
        resources = _resources(aws_s3_bucket=[_named("my_bucket")])
        results = check_s3_request_metrics(resources)
        assert results[0].passed is False

    def test_produces_one_result_per_bucket(self):
        resources = _resources(
            aws_s3_bucket=[_named("bucket_a"), _named("bucket_b")],
        )
        results = check_s3_request_metrics(resources)
        assert len(results) == 2

    def test_returns_empty_when_no_buckets(self):
        assert check_s3_request_metrics({}) == []


# ---------------------------------------------------------------------------
# Observability — check_cloudwatch_dashboard_exists
# ---------------------------------------------------------------------------


class TestCloudwatchDashboardExists:
    def test_passes_when_dashboard_exists(self):
        resources = _resources(
            aws_cloudwatch_dashboard=[_named("my_dashboard", dashboard_name="ops")]
        )
        results = check_cloudwatch_dashboard_exists(resources)
        assert results[0].passed is True
        assert results[0].rule_id == "cloudwatch_dashboard_exists"

    def test_fails_when_no_dashboards(self):
        results = check_cloudwatch_dashboard_exists({})
        assert results[0].passed is False

    def test_severity_is_low(self):
        results = check_cloudwatch_dashboard_exists({})
        assert results[0].severity == "low"
