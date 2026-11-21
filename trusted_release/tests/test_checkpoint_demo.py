"""Keep the independent-state rollback experiment executable and honestly scoped."""

import json
import subprocess
import sys


def test_checkpoint_demo_runs_original_b_chaincode_with_real_c_signatures():
    result = subprocess.run([sys.executable, "-B", "-m", "trusted_release.checkpoint_demo"],
                            capture_output=True, text=True, encoding="utf-8", timeout=45)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["backend"] == "b-chaincode-memory"
    assert report["live_fabric"] is False
    assert report["pass"] is True
    assert len(report["cases"]) == 10
    assert all(case["pass"] is True for case in report["cases"])
    rollback = next(row for row in report["cases"] if row["case"] == "whole_database_rollback")
    assert rollback["actual"] == "CHECKPOINT_MISMATCH"
    assert rollback["local_signature_valid"] is True
    assert "PRIVATE KEY" not in result.stdout


def test_live_demo_requires_separate_reader_and_publisher_arguments():
    result = subprocess.run([sys.executable, "-B", "-m", "trusted_release.checkpoint_demo",
                             "--fabric-reader", "not-present.json"],
                            capture_output=True, text=True, encoding="utf-8", timeout=15)
    assert result.returncode == 2
    assert "--fabric-publisher" in result.stderr
