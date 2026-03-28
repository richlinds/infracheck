from infracheck.rules.fault_tolerance import (
    check_rds_backup_retention,
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
