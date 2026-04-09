from __future__ import annotations

import shutil
from pathlib import Path

from solosec.aggregate import build_report, compute_human_summary, normalize_severity

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _copy_fixture(name: str, destination: Path) -> None:
    shutil.copyfile(FIXTURE_DIR / name, destination / name)


def test_normalize_severity_maps_tool_specific_values() -> None:
    assert normalize_severity("crit") == "CRITICAL"
    assert normalize_severity("warning") == "MEDIUM"
    assert normalize_severity(None) == "UNKNOWN"


def test_build_report_reads_all_supported_tools(tmp_path: Path) -> None:
    _copy_fixture("trivy.json", tmp_path)
    _copy_fixture("semgrep.json", tmp_path)
    _copy_fixture("gitleaks.json", tmp_path)
    _copy_fixture("zap.json", tmp_path)

    findings, report = build_report(tmp_path)

    assert len(findings) == 4
    assert report["summary"]["tools_run"] == ["Trivy", "Semgrep", "Gitleaks", "ZAP"]
    assert findings[0].severity == "CRITICAL"
    assert report["findings"][0]["tool"] == "Gitleaks"


def test_compute_human_summary_groups_breakdown_by_category(tmp_path: Path) -> None:
    _copy_fixture("trivy.json", tmp_path)
    _copy_fixture("gitleaks.json", tmp_path)

    findings, _ = build_report(tmp_path)
    summary = compute_human_summary(findings)

    assert summary.counts["CRITICAL"] == 1
    assert summary.counts["HIGH"] == 1
    assert summary.breakdown["CRITICAL"] == {"Secrets": 1}
    assert summary.breakdown["HIGH"] == {"Deps": 1}
