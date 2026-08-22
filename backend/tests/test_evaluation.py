from backend.app.evaluation.metrics import EvaluatorEngine
from backend.app.evaluation.bandit_runner import BanditRunner


def test_evaluator_engine_metrics():
    result = EvaluatorEngine.evaluate_directory("./evaluation")

    assert result["tp"] == 5
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert result["precision"] == 100.0
    assert result["recall"] == 100.0
    assert result["f1_score"] == 100.0


def test_bandit_runner_metrics():
    result = BanditRunner.evaluate_bandit("./evaluation")
    if result is not None:
        assert result["tool_name"] == "Bandit Baseline"
        assert result["tp"] >= 1
        assert "precision" in result
        assert "f1_score" in result
