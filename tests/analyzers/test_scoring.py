from infracheck.analyzers.scoring import score_results
from infracheck.models import RuleResult


def make_result(passed: bool, severity: str = "high") -> RuleResult:
    return RuleResult(
        rule_id="test_rule",
        category="test",
        severity=severity,
        passed=passed,
        message="test",
    )


class TestScoreResults:
    def test_returns_ten_when_all_pass(self):
        results = [make_result(True), make_result(True), make_result(True)]
        assert score_results(results) == 10

    def test_returns_zero_when_all_fail(self):
        results = [make_result(False), make_result(False), make_result(False)]
        assert score_results(results) == 0

    def test_returns_ten_when_no_results(self):
        assert score_results([]) == 10

    def test_high_severity_failure_costs_more_than_low(self):
        # One high failure vs one low failure — high should score lower
        high_fail = [make_result(False, severity="high"), make_result(True, severity="high")]
        low_fail = [make_result(False, severity="low"), make_result(True, severity="low")]
        assert score_results(high_fail) <= score_results(low_fail)

    def test_mixed_severities_produce_partial_score(self):
        results = [
            make_result(True, severity="high"),
            make_result(False, severity="medium"),
            make_result(True, severity="low"),
        ]
        score = score_results(results)
        assert 0 < score < 10

    def test_score_is_between_zero_and_ten(self):
        results = [
            make_result(True, severity="high"),
            make_result(False, severity="high"),
            make_result(True, severity="medium"),
        ]
        score = score_results(results)
        assert 0 <= score <= 10
