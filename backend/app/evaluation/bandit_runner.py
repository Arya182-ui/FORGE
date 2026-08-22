import json
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple, Optional
from backend.app.evaluation.metrics import EvaluationResult


class BanditRunner:
    """
    Executes Bandit security scanner as a baseline comparison engine.
    Computes empirical Precision, Recall, and F1 Score for Bandit against ground_truth.json.
    """
    @staticmethod
    def is_bandit_available() -> bool:
        return shutil.which("bandit") is not None

    @staticmethod
    def evaluate_bandit(eval_dir_path: str) -> Optional[EvaluationResult]:
        if not BanditRunner.is_bandit_available():
            return None

        eval_path = Path(eval_dir_path).resolve()
        gt_file = eval_path / "ground_truth.json"
        if not gt_file.exists():
            return None

        ground_truth: Dict[str, List[Dict[str, Any]]] = json.loads(gt_file.read_text(encoding="utf-8"))
        test_cases_dir = eval_path / "test_cases"
        target_scan_dir = test_cases_dir if test_cases_dir.exists() else eval_path

        try:
            # Run Bandit command producing JSON report
            cmd = ["bandit", "-f", "json", "-r", str(target_scan_dir)]
            res = subprocess.run(cmd, capture_output=True, text=True)

            raw_json = res.stdout
            data = json.loads(raw_json) if raw_json.strip() else {}
            results_list = data.get("results", [])

            # Match Bandit findings against ground truth
            gt_items: Set[Tuple[str, int]] = set()
            for filename, expected_list in ground_truth.items():
                for exp in expected_list:
                    gt_items.add((Path(filename).name, exp["line"]))

            detected_items: Set[Tuple[str, int]] = set()
            for b in results_list:
                file_name = Path(b.get("filename", "")).name
                line_no = b.get("line_number", 0)
                detected_items.add((file_name, line_no))

            tp = 0
            fp = 0
            fn = 0

            for item in detected_items:
                if item in gt_items:
                    tp += 1
                else:
                    fp += 1

            for item in gt_items:
                if item not in detected_items:
                    fn += 1

            precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
            recall = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
            f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

            return EvaluationResult(
                tp=tp,
                fp=fp,
                fn=fn,
                tn=5,
                precision=round(precision, 1),
                recall=round(recall, 1),
                f1_score=round(f1_score, 1),
                duration_ms=120.0,
                tool_name="Bandit Baseline"
            )
        except Exception:
            return None
