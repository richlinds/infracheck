"""Unit tests for all rule functions."""

import json

from infracheck.rules.fault_tolerance import (
    check_ecs_min_healthy_percent,
    check_s3_versioning,
    check_sns_topic_dlq,
)
from infracheck.rules.observability import (
    check_ecs_container_insights,
    check_rds_enhanced_monitoring,
    check_s3_server_access_logging,
)
from infracheck.rules.scalability import (
    check_ecs_service_autoscaling,
    check_sqs_max_receive_count,
)
from infracheck.rules.security import (
    check_lambda_no_secrets_in_env,
    check_rds_encryption,
    check_s3_encryption,
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
