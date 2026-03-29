from infracheck.analyzers.engine import run
from infracheck.models import Report


class TestEngine:
    def test_returns_report(self):
        report = run(path="./infra", resources={})
        assert isinstance(report, Report)

    def test_report_has_four_categories(self):
        report = run(path="./infra", resources={})
        assert len(report.categories) == 4

    def test_report_path_is_set(self):
        report = run(path="./infra", resources={})
        assert report.path == "./infra"

    def test_overall_score_is_less_than_ten_when_no_resources(self):
        # check_cloudwatch_alarms_exist always fires — it fails when no alarms are present,
        # so even empty resources will produce at least one failure and lower the overall score
        report = run(path="./infra", resources={})
        assert report.overall_score < 10

    def test_overall_score_drops_when_rules_fail(self):
        resources = {
            # RDS instance with no Multi-AZ, no backup retention, publicly accessible
            "aws_db_instance": [{"_name": "my_db", "publicly_accessible": True}],
        }
        report = run(path="./infra", resources=resources)
        assert report.overall_score < 10

    def test_category_names_are_correct(self):
        report = run(path="./infra", resources={})
        category_names = {category.name for category in report.categories}
        assert category_names == {"fault_tolerance", "scalability", "security", "observability"}

    def test_failed_findings_returns_only_failures(self):
        resources = {
            "aws_db_instance": [{"_name": "my_db", "publicly_accessible": True}],
        }
        report = run(path="./infra", resources=resources)
        assert all(not finding.passed for finding in report.failed_findings)

    def test_passed_findings_returns_only_passes(self):
        resources = {
            "aws_db_instance": [{"_name": "my_db", "publicly_accessible": True}],
        }
        report = run(path="./infra", resources=resources)
        assert all(finding.passed for finding in report.passed_findings)
