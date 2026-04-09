from __future__ import annotations

import argparse
import json
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Final, cast

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ._models import (
    DEFAULT_FAIL_ON_SEVERITIES,
    AggregateCliOptions,
    AggregateReportDict,
    Finding,
    HumanSummary,
    Severity,
)

SEVERITY_ALIASES: Final[dict[str, Severity]] = {
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "HIGH": "HIGH",
    "WARN": "MEDIUM",
    "WARNING": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATION": "INFO",
    "INFORMATIONAL": "INFO",
    "UNKNOWN": "UNKNOWN",
}
TOOL_CATEGORIES: Final[dict[str, str]] = {
    "gitleaks": "Secrets",
    "semgrep": "Code",
    "trivy": "Deps",
    "zap": "ZAP",
}
SEVERITY_RANK: Final[dict[Severity, int]] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}
REPORT_FILES: Final[tuple[tuple[str, str], ...]] = (
    ("Trivy", "trivy.json"),
    ("Semgrep", "semgrep.json"),
    ("Gitleaks", "gitleaks.json"),
    ("ZAP", "zap.json"),
)
ZAP_RISK_MAP: Final[dict[str, Severity]] = {
    "3": "HIGH",
    "2": "MEDIUM",
    "1": "LOW",
    "0": "INFO",
}


def normalize_severity(value: object) -> Severity:
    try:
        normalized = str(value).strip().upper()
    except (TypeError, ValueError):
        return "UNKNOWN"

    if normalized == "":
        return "UNKNOWN"
    return SEVERITY_ALIASES.get(normalized, "UNKNOWN")


def _category_for_tool(tool: str) -> str:
    normalized = tool.strip().lower()
    return TOOL_CATEGORIES.get(normalized, tool or "Other")


def compute_human_summary(findings: Sequence[Finding]) -> HumanSummary:
    summary = HumanSummary(total=len(findings))
    for finding in findings:
        severity = normalize_severity(finding.severity)
        summary.counts[severity] += 1
        category = _category_for_tool(finding.tool)
        severity_breakdown = summary.breakdown[severity]
        severity_breakdown[category] = severity_breakdown.get(category, 0) + 1
    return summary


def _format_breakdown(items: Mapping[str, int], order: Sequence[str] | None = None) -> str:
    if not items:
        return ""
    keys = list(order) if order is not None else sorted(items)
    return ", ".join(f"{key}: {items[key]}" for key in keys if items.get(key))


def _summary_rows() -> tuple[tuple[str, Severity, str, bool], ...]:
    return (
        ("Critical", "CRITICAL", "red", True),
        ("High", "HIGH", "bright_red", True),
        ("Medium", "MEDIUM", "yellow", False),
    )


def _status_summary(failed: bool) -> tuple[str, str, str]:
    if failed:
        return "red", "FAIL", "High/Critical issues found."
    return "green", "PASS", "No High/Critical issues found."


def print_human_summary(
    *,
    findings: Sequence[Finding],
    output_file: str | Path,
    fail_on_severities: Sequence[Severity] | None = None,
) -> bool:
    summary = compute_human_summary(findings)
    counts = summary.counts
    breakdown = summary.breakdown
    failure_thresholds = tuple(fail_on_severities or DEFAULT_FAIL_ON_SEVERITIES)
    failed = any(counts[severity] > 0 for severity in failure_thresholds)
    output_path = str(output_file)

    console = Console()
    console.print("-" * 50)
    console.print(Text("SCAN COMPLETE", style="bold cyan"))
    console.print("-" * 50)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", justify="left")
    table.add_column("Count", justify="right")
    table.add_column("Breakdown", justify="left")

    for label, severity, color, show_breakdown in _summary_rows():
        breakdown_text = ""
        if show_breakdown:
            breakdown_text = _format_breakdown(
                breakdown[severity],
                order=["Secrets", "Code", "Deps", "ZAP"],
            )
        table.add_row(
            f"[{color}]{label}[/{color}]",
            str(counts[severity]),
            breakdown_text,
        )

    console.print(table)
    console.print("-" * 50)
    status_style, status_label, summary_line = _status_summary(failed)
    status_message = (
        f"[{status_style}]{status_label}:[/{status_style}] {summary_line} See {output_path}"
    )
    console.print(status_message)
    return failed


def _as_mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return None


def _iter_list_items(value: object) -> Iterator[object]:
    if isinstance(value, list):
        yield from cast(list[object], value)


def _get_string(mapping: Mapping[str, object], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) and value.strip() else None


def _get_int(mapping: Mapping[str, object], key: str) -> int | None:
    value = mapping.get(key)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _iter_mappings(value: object) -> Iterator[Mapping[str, object]]:
    for item in _iter_list_items(value):
        narrowed = _as_mapping(item)
        if narrowed is not None:
            yield narrowed


def load_json(path: str | Path) -> object | None:
    file_path = Path(path)
    if not file_path.exists():
        return None
    try:
        raw_data: object = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        print(f"Warning: Could not parse {file_path.name}: {error}")
        return None
    return raw_data


def _trivy_title(vulnerability: Mapping[str, object]) -> str:
    return (
        _get_string(vulnerability, "Title")
        or _get_string(vulnerability, "VulnerabilityID")
        or "Vulnerability"
    )


def _build_trivy_finding(vulnerability: Mapping[str, object], target: str) -> Finding:
    package_name = _get_string(vulnerability, "PkgName") or "Unknown package"
    installed_version = _get_string(vulnerability, "InstalledVersion") or "Unknown version"
    return Finding(
        tool="Trivy",
        severity=normalize_severity(vulnerability.get("Severity")),
        file=target,
        description=f"{package_name} {installed_version} - {_trivy_title(vulnerability)}",
        fix=_get_string(vulnerability, "FixedVersion") or "No fix available",
    )


def _parse_trivy_data(raw_data: object | None) -> list[Finding]:
    root = _as_mapping(raw_data)
    if root is None:
        return []

    findings: list[Finding] = []
    for result in _iter_mappings(root.get("Results")):
        target = _get_string(result, "Target") or "Unknown"
        for vulnerability in _iter_mappings(result.get("Vulnerabilities")):
            findings.append(_build_trivy_finding(vulnerability, target))
    return findings


def parse_trivy(report_dir: str | Path) -> list[Finding]:
    return _parse_trivy_data(load_json(Path(report_dir) / "trivy.json"))


def _parse_semgrep_data(raw_data: object | None) -> list[Finding]:
    root = _as_mapping(raw_data)
    if root is None:
        return []

    findings: list[Finding] = []
    for result in _iter_mappings(root.get("results")):
        extra = _as_mapping(result.get("extra")) or {}
        start = _as_mapping(result.get("start")) or {}
        findings.append(
            Finding(
                tool="Semgrep",
                severity=normalize_severity(extra.get("severity")),
                file=_get_string(result, "path") or "Unknown",
                line=_get_int(start, "line"),
                description=_get_string(extra, "message") or "Semgrep finding",
                rule_id=_get_string(result, "check_id") or "Unknown",
            )
        )
    return findings


def parse_semgrep(report_dir: str | Path) -> list[Finding]:
    return _parse_semgrep_data(load_json(Path(report_dir) / "semgrep.json"))


def _parse_gitleaks_data(raw_data: object | None) -> list[Finding]:
    findings: list[Finding] = []
    for raw_leak in _iter_list_items(raw_data):
        leak = _as_mapping(raw_leak)
        if leak is None:
            continue
        rule_id = _get_string(leak, "RuleID") or "Unknown"
        findings.append(
            Finding(
                tool="Gitleaks",
                severity="CRITICAL",
                file=_get_string(leak, "File") or "Unknown",
                line=_get_int(leak, "StartLine"),
                description=f"Secret detected: {rule_id}",
                snippet="REDACTED",
            )
        )
    return findings


def _extract_zap_target_url(alert: Mapping[str, object]) -> str:
    for instance in _iter_mappings(alert.get("instances")):
        uri = _get_string(instance, "uri")
        if uri is not None:
            return uri
    return "URL Target"


def _build_zap_finding(alert: Mapping[str, object]) -> Finding:
    severity = ZAP_RISK_MAP.get(str(alert.get("riskcode")), "UNKNOWN")
    return Finding(
        tool="ZAP",
        severity=severity,
        file=_extract_zap_target_url(alert),
        description=_get_string(alert, "alert") or "ZAP alert",
        solution=_get_string(alert, "solution"),
    )


def parse_gitleaks(report_dir: str | Path) -> list[Finding]:
    return _parse_gitleaks_data(load_json(Path(report_dir) / "gitleaks.json"))


def _parse_zap_data(raw_data: object | None) -> list[Finding]:
    root = _as_mapping(raw_data)
    if root is None:
        return []

    findings: list[Finding] = []

    for site in _iter_mappings(root.get("site")):
        for alert in _iter_mappings(site.get("alerts")):
            findings.append(_build_zap_finding(alert))
    return findings


def parse_zap(report_dir: str | Path) -> list[Finding]:
    return _parse_zap_data(load_json(Path(report_dir) / "zap.json"))


def _severity_sort_key(finding: Finding) -> int:
    return SEVERITY_RANK[normalize_severity(finding.severity)]


def _load_reports(report_dir: Path) -> dict[str, object | None]:
    return {tool_name: load_json(report_dir / filename) for tool_name, filename in REPORT_FILES}


def detect_tools_run(reports: Mapping[str, object | None]) -> list[str]:
    return [tool_name for tool_name, _ in REPORT_FILES if reports.get(tool_name) is not None]


def build_report(report_dir: str | Path) -> tuple[list[Finding], AggregateReportDict]:
    directory = Path(report_dir)
    reports = _load_reports(directory)
    findings = [
        *_parse_trivy_data(reports["Trivy"]),
        *_parse_semgrep_data(reports["Semgrep"]),
        *_parse_gitleaks_data(reports["Gitleaks"]),
        *_parse_zap_data(reports["ZAP"]),
    ]
    findings.sort(key=_severity_sort_key)
    report: AggregateReportDict = {
        "summary": {
            "total_issues": len(findings),
            "tools_run": detect_tools_run(reports),
        },
        "findings": [finding.to_dict() for finding in findings],
    }
    return findings, report


def write_report(output_file: str | Path, report: AggregateReportDict) -> None:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def generate_report(
    *,
    report_dir: str | Path,
    output_file: str | Path,
    fail_on_severities: Sequence[Severity] | None = None,
) -> bool:
    findings, report = build_report(report_dir)
    write_report(output_file, report)
    print(f"Generated {output_file} with {len(findings)} issues.")
    return print_human_summary(
        findings=findings,
        output_file=output_file,
        fail_on_severities=fail_on_severities,
    )


def _parse_args(argv: list[str] | None = None) -> AggregateCliOptions:
    parser = argparse.ArgumentParser(
        prog="solosec-aggregate",
        description=(
            "Aggregate security scanner reports (Trivy, Semgrep, Gitleaks, ZAP) "
            "into a single JSON file."
        ),
    )
    parser.add_argument(
        "report_dir",
        help="Directory containing tool JSON outputs (for example: trivy.json, semgrep.json)",
    )
    parser.add_argument("output_file", help="Path to write the aggregated JSON report")
    namespace = parser.parse_args(argv)
    return AggregateCliOptions(
        report_dir=Path(cast(str, namespace.report_dir)).resolve(),
        output_file=Path(cast(str, namespace.output_file)).resolve(),
    )


def main(argv: list[str] | None = None) -> int:
    options = _parse_args(argv)
    print(f"--- Aggregating Reports from {options.report_dir} ---")
    failed = generate_report(report_dir=options.report_dir, output_file=options.output_file)
    return 1 if failed else 0
