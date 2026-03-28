from infracheck.rules.fault_tolerance import (
    check_dynamodb_pitr,
    check_lambda_dlq,
    check_rds_backup_retention,
    check_rds_deletion_protection,
    check_rds_multi_az,
    check_sqs_dlq,
)


class TestSqsDlq:
    def test_passes_when_dlq_configured(self):
        resources = {
            "aws_sqs_queue": [
                {
                    "_name": "my_queue",
                    "redrive_policy": '{"deadLetterTargetArn": "arn:aws:sqs:..."}',
                }
            ]
        }
        results = check_sqs_dlq(resources)
        assert results[0].passed is True

    def test_fails_when_dlq_missing(self):
        resources = {"aws_sqs_queue": [{"_name": "my_queue", "name": "my-queue"}]}
        results = check_sqs_dlq(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_queues(self):
        results = check_sqs_dlq({})
        assert results == []

    def test_resource_name_is_set(self):
        resources = {"aws_sqs_queue": [{"_name": "my_queue", "name": "my-queue"}]}
        results = check_sqs_dlq(resources)
        assert results[0].resource == "my_queue"


class TestRdsMultiAz:
    def test_passes_when_multi_az_enabled(self):
        resources = {"aws_db_instance": [{"_name": "my_db", "multi_az": True}]}
        results = check_rds_multi_az(resources)
        assert results[0].passed is True

    def test_fails_when_multi_az_disabled(self):
        resources = {"aws_db_instance": [{"_name": "my_db", "multi_az": False}]}
        results = check_rds_multi_az(resources)
        assert results[0].passed is False

    def test_fails_when_multi_az_not_set(self):
        resources = {"aws_db_instance": [{"_name": "my_db"}]}
        results = check_rds_multi_az(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_instances(self):
        results = check_rds_multi_az({})
        assert results == []


class TestRdsBackupRetention:
    def test_passes_when_retention_meets_minimum(self):
        resources = {"aws_db_instance": [{"_name": "my_db", "backup_retention_period": 7}]}
        results = check_rds_backup_retention(resources)
        assert results[0].passed is True

    def test_passes_when_retention_exceeds_minimum(self):
        resources = {"aws_db_instance": [{"_name": "my_db", "backup_retention_period": 30}]}
        results = check_rds_backup_retention(resources)
        assert results[0].passed is True

    def test_fails_when_retention_below_minimum(self):
        resources = {"aws_db_instance": [{"_name": "my_db", "backup_retention_period": 3}]}
        results = check_rds_backup_retention(resources)
        assert results[0].passed is False

    def test_fails_when_retention_not_set(self):
        resources = {"aws_db_instance": [{"_name": "my_db"}]}
        results = check_rds_backup_retention(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_instances(self):
        results = check_rds_backup_retention({})
        assert results == []


class TestLambdaDlq:
    def test_passes_when_dlq_configured(self):
        resources = {
            "aws_lambda_function": [{
                "_name": "my_func",
                "dead_letter_config": {"target_arn": "arn:aws:sqs:..."},
            }]
        }
        results = check_lambda_dlq(resources)
        assert results[0].passed is True

    def test_passes_when_dead_letter_config_is_list(self):
        resources = {
            "aws_lambda_function": [{
                "_name": "my_func",
                "dead_letter_config": [{"target_arn": "arn:aws:sqs:..."}],
            }]
        }
        results = check_lambda_dlq(resources)
        assert results[0].passed is True

    def test_fails_when_dead_letter_config_not_set(self):
        resources = {"aws_lambda_function": [{"_name": "my_func"}]}
        results = check_lambda_dlq(resources)
        assert results[0].passed is False

    def test_fails_when_target_arn_is_empty(self):
        resources = {
            "aws_lambda_function": [{
                "_name": "my_func",
                "dead_letter_config": {"target_arn": ""},
            }]
        }
        results = check_lambda_dlq(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_functions(self):
        results = check_lambda_dlq({})
        assert results == []


class TestDynamodbPitr:
    def test_passes_when_pitr_enabled(self):
        resources = {
            "aws_dynamodb_table": [{
                "_name": "my_table",
                "point_in_time_recovery": {"enabled": True},
            }]
        }
        results = check_dynamodb_pitr(resources)
        assert results[0].passed is True

    def test_passes_when_pitr_is_list(self):
        resources = {
            "aws_dynamodb_table": [{
                "_name": "my_table",
                "point_in_time_recovery": [{"enabled": True}],
            }]
        }
        results = check_dynamodb_pitr(resources)
        assert results[0].passed is True

    def test_fails_when_pitr_disabled(self):
        resources = {
            "aws_dynamodb_table": [{
                "_name": "my_table",
                "point_in_time_recovery": {"enabled": False},
            }]
        }
        results = check_dynamodb_pitr(resources)
        assert results[0].passed is False

    def test_fails_when_pitr_not_set(self):
        resources = {"aws_dynamodb_table": [{"_name": "my_table"}]}
        results = check_dynamodb_pitr(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_tables(self):
        results = check_dynamodb_pitr({})
        assert results == []


class TestRdsDeletionProtection:
    def test_passes_when_deletion_protection_enabled(self):
        resources = {"aws_db_instance": [{"_name": "my_db", "deletion_protection": True}]}
        results = check_rds_deletion_protection(resources)
        assert results[0].passed is True

    def test_fails_when_deletion_protection_disabled(self):
        resources = {"aws_db_instance": [{"_name": "my_db", "deletion_protection": False}]}
        results = check_rds_deletion_protection(resources)
        assert results[0].passed is False

    def test_fails_when_deletion_protection_not_set(self):
        resources = {"aws_db_instance": [{"_name": "my_db"}]}
        results = check_rds_deletion_protection(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_instances(self):
        results = check_rds_deletion_protection({})
        assert results == []
