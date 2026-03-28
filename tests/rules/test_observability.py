from infracheck.rules.observability import (
    check_alb_access_logging,
    check_cloudtrail_cloudwatch_integration,
    check_cloudwatch_alarms_exist,
    check_lambda_log_groups,
    check_lambda_xray_tracing,
    check_log_group_retention,
    check_vpc_flow_logs,
)


class TestCloudwatchAlarmsExist:
    def test_passes_when_alarms_exist(self):
        resources = {
            "aws_cloudwatch_metric_alarm": [{"_name": "cpu_alarm", "alarm_name": "high-cpu"}]
        }
        results = check_cloudwatch_alarms_exist(resources)
        assert results[0].passed is True

    def test_fails_when_no_alarms(self):
        results = check_cloudwatch_alarms_exist({})
        assert results[0].passed is False


class TestLambdaLogGroups:
    def test_passes_when_log_group_exists(self):
        resources = {
            "aws_lambda_function": [{"_name": "my_func", "function_name": "my-func"}],
            "aws_cloudwatch_log_group": [{"_name": "my_func_logs", "name": "/aws/lambda/my-func"}],
        }
        results = check_lambda_log_groups(resources)
        assert results[0].passed is True

    def test_fails_when_log_group_missing(self):
        resources = {
            "aws_lambda_function": [{"_name": "my_func", "function_name": "my-func"}],
        }
        results = check_lambda_log_groups(resources)
        assert results[0].passed is False

    def test_fails_when_log_group_name_does_not_match(self):
        resources = {
            "aws_lambda_function": [{"_name": "my_func", "function_name": "my-func"}],
            "aws_cloudwatch_log_group": [{"_name": "other_logs", "name": "/aws/lambda/other-func"}],
        }
        results = check_lambda_log_groups(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_lambdas(self):
        results = check_lambda_log_groups({})
        assert results == []


class TestLambdaXrayTracing:
    def test_passes_when_xray_tracing_active(self):
        resources = {
            "aws_lambda_function": [{"_name": "my_func", "tracing_config": {"mode": "Active"}}]
        }
        results = check_lambda_xray_tracing(resources)
        assert results[0].passed is True

    def test_passes_when_tracing_config_is_list(self):
        resources = {
            "aws_lambda_function": [{"_name": "my_func", "tracing_config": [{"mode": "Active"}]}]
        }
        results = check_lambda_xray_tracing(resources)
        assert results[0].passed is True

    def test_fails_when_tracing_mode_is_passthrough(self):
        resources = {
            "aws_lambda_function": [{"_name": "my_func", "tracing_config": {"mode": "PassThrough"}}]
        }
        results = check_lambda_xray_tracing(resources)
        assert results[0].passed is False

    def test_fails_when_tracing_config_not_set(self):
        resources = {"aws_lambda_function": [{"_name": "my_func"}]}
        results = check_lambda_xray_tracing(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_functions(self):
        results = check_lambda_xray_tracing({})
        assert results == []


class TestLogGroupRetention:
    def test_passes_when_retention_set(self):
        resources = {"aws_cloudwatch_log_group": [{"_name": "my_logs", "retention_in_days": 30}]}
        results = check_log_group_retention(resources)
        assert results[0].passed is True

    def test_fails_when_retention_is_zero(self):
        resources = {"aws_cloudwatch_log_group": [{"_name": "my_logs", "retention_in_days": 0}]}
        results = check_log_group_retention(resources)
        assert results[0].passed is False

    def test_fails_when_retention_not_set(self):
        resources = {"aws_cloudwatch_log_group": [{"_name": "my_logs"}]}
        results = check_log_group_retention(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_log_groups(self):
        results = check_log_group_retention({})
        assert results == []


class TestAlbAccessLogging:
    def test_passes_when_access_logging_enabled(self):
        resources = {
            "aws_lb": [
                {
                    "_name": "my_alb",
                    "load_balancer_type": "application",
                    "access_logs": {"enabled": True, "bucket": "my-logs-bucket"},
                }
            ]
        }
        results = check_alb_access_logging(resources)
        assert results[0].passed is True

    def test_passes_when_access_logs_is_list(self):
        resources = {
            "aws_lb": [
                {
                    "_name": "my_alb",
                    "load_balancer_type": "application",
                    "access_logs": [{"enabled": True, "bucket": "my-logs-bucket"}],
                }
            ]
        }
        results = check_alb_access_logging(resources)
        assert results[0].passed is True

    def test_fails_when_access_logging_disabled(self):
        resources = {
            "aws_lb": [
                {
                    "_name": "my_alb",
                    "load_balancer_type": "application",
                    "access_logs": {"enabled": False},
                }
            ]
        }
        results = check_alb_access_logging(resources)
        assert results[0].passed is False

    def test_fails_when_access_logs_not_set(self):
        resources = {"aws_lb": [{"_name": "my_alb", "load_balancer_type": "application"}]}
        results = check_alb_access_logging(resources)
        assert results[0].passed is False

    def test_skips_non_application_load_balancers(self):
        resources = {"aws_lb": [{"_name": "my_nlb", "load_balancer_type": "network"}]}
        results = check_alb_access_logging(resources)
        assert results == []

    def test_returns_empty_when_no_load_balancers(self):
        results = check_alb_access_logging({})
        assert results == []


class TestCloudtrailCloudwatchIntegration:
    def test_passes_when_cloudwatch_integration_set(self):
        resources = {
            "aws_cloudtrail": [
                {
                    "_name": "my_trail",
                    "cloud_watch_logs_group_arn": "arn:aws:logs:...",
                }
            ]
        }
        results = check_cloudtrail_cloudwatch_integration(resources)
        assert results[0].passed is True

    def test_fails_when_cloudwatch_integration_not_set(self):
        resources = {"aws_cloudtrail": [{"_name": "my_trail"}]}
        results = check_cloudtrail_cloudwatch_integration(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_trails(self):
        results = check_cloudtrail_cloudwatch_integration({})
        assert results == []


class TestVpcFlowLogs:
    def test_passes_when_flow_logs_exist_for_vpc(self):
        resources = {
            "aws_vpc": [{"_name": "my_vpc"}],
            "aws_flow_log": [{"_name": "my_flow_log", "vpc_id": "my_vpc"}],
        }
        results = check_vpc_flow_logs(resources)
        assert results[0].passed is True

    def test_fails_when_no_flow_logs_for_vpc(self):
        resources = {
            "aws_vpc": [{"_name": "my_vpc"}],
        }
        results = check_vpc_flow_logs(resources)
        assert results[0].passed is False

    def test_fails_when_flow_log_belongs_to_different_vpc(self):
        resources = {
            "aws_vpc": [{"_name": "my_vpc"}],
            "aws_flow_log": [{"_name": "other_flow_log", "vpc_id": "other_vpc"}],
        }
        results = check_vpc_flow_logs(resources)
        assert results[0].passed is False

    def test_returns_empty_when_no_vpcs(self):
        results = check_vpc_flow_logs({})
        assert results == []
