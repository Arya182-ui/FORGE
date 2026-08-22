from backend.app.scanner.engine import ScannerEngine


def test_scanner_engine_on_vulnerable_examples():
    engine = ScannerEngine()
    report = engine.run_scan("examples/vulnerable", save_to_db=False)

    summary = report.summary
    assert summary.total_findings_count >= 8
    assert summary.scanned_files_count >= 5
    assert len(report.findings) == summary.total_findings_count

    # Check rule IDs present
    rule_ids = {f.rule_id for f in report.findings}
    assert "PY-SQL-001" in rule_ids
    assert "PY-CMD-001" in rule_ids
    assert "PY-EVAL-001" in rule_ids
    assert "PY-SEC-001" in rule_ids
    assert "PY-DESER-001" in rule_ids


def test_scanner_engine_deduplication():
    engine = ScannerEngine()
    report = engine.run_scan("examples/vulnerable", save_to_db=False)

    fingerprints = [f.fingerprint for f in report.findings]
    assert len(fingerprints) == len(set(fingerprints)), "Fingerprints must be unique after deduplication."
